package discover

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"scan-website/models"
	"strings"
	"sync"
)

// 手动释放内存，防止 OOM //3.17
func freeMem() {
	runtime.GC()
	debug.FreeOSMemory()
}

// JSONL 文件写入，使用缓冲减少 I/O 竞争
func writeResultToJSONLFile(fileName string, results []models.DomainResult, fileLock *sync.Mutex) error {
	fileLock.Lock()
	defer fileLock.Unlock()

	// 使用 bufio 缓冲写入
	file, err := os.OpenFile(fileName, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("error opening file: %v", err)
	}
	defer file.Close()

	writer := bufio.NewWriterSize(file, 64*1024)
	for _, result := range results {
		jsonBytes, err := json.Marshal(result)
		if err != nil {
			return fmt.Errorf("error marshaling JSON: %v", err)
		}
		writer.Write(append(jsonBytes, '\n'))
	}
	writer.Flush() // 避免频繁 file.Sync()
	return nil
}

// 逐行读取 CSV，避免一次性加载大量数据
func fetchDomainsFromCSVStream(filename string, processFunc func(string, int)) error {
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("failed to open CSV file: %v", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	lineIndex := 0
	for {
		record, err := reader.Read()
		if err != nil {
			break
		}

		if len(record) > 1 {
			domain := strings.TrimSpace(record[1])
			//domain := strings.TrimSpace(record[0]) //9.13
			if domain != "" {
				processFunc(domain, lineIndex)
			}
		}
		lineIndex++
	}
	return nil
}
func Process() {
	var wg sync.WaitGroup
	fileLock := &sync.Mutex{} // 用于写入 JSONL 时加锁
	fileName := "init.jsonl"
	//csvFile := "tranco_KJ7VW.csv"
	//csvFile := "remaining_domains.csv" //3.19续
	csvFile := "/home/wzq/scan-website/domains.csv"

	// 控制并发的信号量，限制最大 Goroutine 数量
	semaphore := make(chan struct{}, 200)
	batchSize := 500
	var currentBatch []models.DomainResult
	var resultsMutex sync.Mutex

	// 使用流式读取 CSV
	err := fetchDomainsFromCSVStream(csvFile, func(domain string, index int) {
		wg.Add(1)
		semaphore <- struct{}{} // 占用一个信号量

		go func(domain string, index int) {
			defer wg.Done()
			defer func() { <-semaphore }() // 释放信号量

			// 处理域名
			domainResult := ProcessDomain(domain)
			domainResult.Domain_id = index + 1

			// 批量写入 JSONL
			resultsMutex.Lock()
			currentBatch = append(currentBatch, domainResult)
			if len(currentBatch) >= batchSize {
				if err := writeResultToJSONLFile(fileName, currentBatch, fileLock); err != nil {
					fmt.Printf("Error writing batch to JSONL: %v\n", err)
				}
				currentBatch = nil // 清空批次
				freeMem()          // 释放内存，防止 OOM//3.17
			}
			resultsMutex.Unlock()
		}(domain, index)
	})

	if err != nil {
		fmt.Printf("Failed to fetch domains from CSV: %v\n", err)
		return
	}

	// 等待所有任务完成
	wg.Wait()

	// 处理剩余的批次
	if len(currentBatch) > 0 {
		if err := writeResultToJSONLFile(fileName, currentBatch, fileLock); err != nil {
			fmt.Printf("Error writing last batch to JSONL: %v\n", err)
		}
		freeMem() // 释放最后的内存
	}

	fmt.Printf("Results successfully saved to %s\n", fileName)
}

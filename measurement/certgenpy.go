package measurement

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"scan-website/models"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/beevik/etree"
)

func CountDomains_Certinfo(inputFile string) {
	file, err := os.Open(inputFile)
	if err != nil {
		log.Fatalf("Failed to open file: %v", err)
	}
	defer file.Close()

	reader := bufio.NewReader(file)
	sem := make(chan struct{}, 50) // 控制并发数
	var wg sync.WaitGroup

	// 统计变量
	var (
		domainProcessed                int64
		totalautodiscover_cert         = make(map[string]struct{})
		no_trusted_autodiscover        = make(map[string]struct{})
		no_match_hostname_autodiscover = make(map[string]struct{})
		no_indate_autodiscover         = make(map[string]struct{})
		totalautoconfig_cert           = make(map[string]struct{})
		no_trusted_autoconfig          = make(map[string]struct{})
		no_match_hostname_autoconfig   = make(map[string]struct{})
		no_indate_autoconfig           = make(map[string]struct{})
	)

	// 互斥锁保护共享变量
	var mu sync.Mutex

	for {
		line, err := reader.ReadString('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatalf("Error reading line: %v", err)
		}

		var obj models.DomainResult
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			log.Printf("❌ JSON 解析失败，跳过此行: %v", err)
			continue
		}

		sem <- struct{}{} // 占位
		wg.Add(1)
		go func(obj models.DomainResult) {
			defer wg.Done()
			defer func() { <-sem }()

			domain := obj.Domain
			atomic.AddInt64(&domainProcessed, 1)

			// Autoconfig 统计
			for _, entry := range obj.Autoconfig {
				if entry.Config != "" {
					doc := etree.NewDocument()
					if err := doc.ReadFromString(entry.Config); err == nil {
						if doc.SelectElement("clientConfig") != nil {
							mu.Lock()
							if entry.CertInfo != nil {
								totalautoconfig_cert[domain] = struct{}{} //如果同一个域名不同路径的证书不一样呢
								if !entry.CertInfo.IsTrusted {
									no_trusted_autoconfig[domain] = struct{}{}
								}
								if !entry.CertInfo.IsHostnameMatch {
									no_match_hostname_autoconfig[domain] = struct{}{}
								}
								if entry.CertInfo.IsExpired {
									no_indate_autoconfig[domain] = struct{}{}
								}
							}

							mu.Unlock()
						}
					}
				}
			}

			// Autodiscover 统计
			for _, entry := range obj.Autodiscover {
				if entry.Config != "" && !strings.HasPrefix(entry.Config, "Bad") && !strings.HasPrefix(entry.Config, "Errorcode") {
					doc := etree.NewDocument()
					if err := doc.ReadFromString(entry.Config); err == nil && doc.SelectElement("Autodiscover") != nil {
						mu.Lock()
						totalautodiscover_cert[domain] = struct{}{}
						if !entry.CertInfo.IsTrusted {
							no_trusted_autodiscover[domain] = struct{}{}
						}
						if !entry.CertInfo.IsHostnameMatch {
							no_match_hostname_autodiscover[domain] = struct{}{}
						}
						if entry.CertInfo.IsExpired {
							no_indate_autodiscover[domain] = struct{}{}
						}
						mu.Unlock()
					}
				}
			}
		}(obj)
	}

	wg.Wait()

	// 输出统计结果
	fmt.Printf("✅ Autodiscover可以获取配置的域名证书数量: %d\n", len(totalautodiscover_cert))
	fmt.Printf("✅ Autodiscover证书不可信任的域名数量: %d\n", len(no_trusted_autodiscover))
	fmt.Printf("✅ Autodiscover证书主机名不匹配的域名数量: %d\n", len(no_match_hostname_autodiscover))
	fmt.Printf("✅ Autodiscover证书过期的域名数量: %d\n", len(no_indate_autodiscover))

	fmt.Printf("✅ Autoconfig可以获取配置的域名证书数量: %d\n", len(totalautoconfig_cert))
	fmt.Printf("✅ Autoconfig证书不可信任的域名数量: %d\n", len(no_trusted_autoconfig))
	fmt.Printf("✅ Autoconfig证书主机名不匹配的域名数量: %d\n", len(no_match_hostname_autoconfig))
	fmt.Printf("✅ Autoconfig证书过期的域名数量: %d\n", len(no_indate_autoconfig))
	fmt.Printf("✅ 一共处理了域名数量: %d\n", domainProcessed)

	// 将 domain_stats 写入文件
	dataToSave := map[string]interface{}{
		"totalautodiscover_cert":         mapToSlice(totalautodiscover_cert),
		"no_trusted_autodiscover":        mapToSlice(no_trusted_autodiscover),
		"no_match_hostname_autodiscover": mapToSlice(no_match_hostname_autodiscover),
		"no_indate_autodiscover":         mapToSlice(no_indate_autodiscover),
		"totalautoconfig_cert":           mapToSlice(totalautoconfig_cert),
		"no_trusted_autoconfig":          mapToSlice(no_trusted_autoconfig),
		"no_match_hostname_autoconfig":   mapToSlice(no_match_hostname_autoconfig),
		"no_indate_autoconfig":           mapToSlice(no_indate_autoconfig),
	}

	if err := saveToJSON("./cert_stats.json", dataToSave); err != nil {
		log.Fatalf("Error saving cert_stats: %v", err)
	}
}

// func mapToSlice(m map[string]struct{}) []string {
// 	slice := make([]string, 0, len(m))
// 	for key := range m {
// 		slice = append(slice, key)
// 	}
// 	return slice
// }

// func saveToJSON(filename string, data interface{}) error {
// 	file, err := os.Create(filename)
// 	if err != nil {
// 		return fmt.Errorf("failed to create file: %v", err)
// 	}
// 	defer file.Close()

// 	encoder := json.NewEncoder(file)
// 	encoder.SetIndent("", "    ") // 设置缩进为 4 个空格
// 	encoder.SetEscapeHTML(false)  // 不转义 HTML 字符

// 	if err := encoder.Encode(data); err != nil {
// 		return fmt.Errorf("failed to encode data to JSON: %v", err)
// 	}

// 	fmt.Printf("✅ %s saved to '%s'.\n", filename, filename)
// 	return nil
// }

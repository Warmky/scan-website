package scan

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
)

type Record struct {
	Domain string `json:"domain"`
	Ok     bool   `json:"ok"`
}

func Extract() {
	inputFile := "/home/wzq/scan-website/scan/results_autodiscover.jsonl"
	outputFile := "/home/wzq/scan-website/scan/ok_domains.txt"

	in, err := os.Open(inputFile)
	if err != nil {
		panic(err)
	}
	defer in.Close()

	out, err := os.Create(outputFile)
	if err != nil {
		panic(err)
	}
	defer out.Close()

	scanner := bufio.NewScanner(in)

	count := 0
	for scanner.Scan() {
		line := scanner.Text()
		var r Record

		// 解析JSON
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			continue
		}

		// 只写 ok == true 的域名
		if r.Ok {
			out.WriteString(r.Domain + "\n")
			count++
		}
	}

	fmt.Printf("完成！共写入 %d 个域名\n", count)
}

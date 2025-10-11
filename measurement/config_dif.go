package measurement

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"scan-website/models"
	"sort"
	"strings"
)

// 输出结果结构
type DiffResult struct {
	Domain       string          `json:"domain"`
	InternalDiff map[string]bool `json:"internal_diff"`
	CrossDiff    bool            `json:"cross_diff"`
}

func uniqueStrings(input []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, s := range input {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}

func comparePortConfigs(results []models.AutodiscoverResult) bool {
	if len(results) <= 1 {
		return false
	}

	var allPorts []map[string][]string
	for _, r := range results {
		portMap := make(map[string][]string)
		for _, p := range r.ScoreDetail.PortsUsage {
			key := p.Protocol
			val := fmt.Sprintf("%s:%d(%s)", p.Host, p.Port, p.SSL)
			portMap[key] = append(portMap[key], val)
		}
		// 去重+排序
		for k := range portMap {
			unique := uniqueStrings(portMap[k])
			sort.Strings(unique)
			portMap[k] = unique
		}
		allPorts = append(allPorts, portMap)
	}

	// 获取所有协议集合
	protocolSet := make(map[string]struct{})
	for _, m := range allPorts {
		for proto := range m {
			protocolSet[proto] = struct{}{}
		}
	}

	// 检查每个协议是否一致
	for proto := range protocolSet {
		var previous []string
		for i, m := range allPorts {
			ports := m[proto]
			if i == 0 {
				previous = ports
			} else if !reflect.DeepEqual(ports, previous) {
				return true // 差异
			}
		}
	}

	// 检查缺失协议
	for _, m := range allPorts {
		for proto := range protocolSet {
			if _, ok := m[proto]; !ok {
				return true
			}
		}
	}

	return false
}

// 支持 Autoconfig
func comparePortConfigsAutoconfig(results []AutoconfigResult) bool {
	if len(results) <= 1 {
		return false
	}

	var allPorts []map[string][]string
	for _, r := range results {
		portMap := make(map[string][]string)
		for _, p := range r.ScoreDetail.PortsUsage {
			key := p.Protocol
			val := fmt.Sprintf("%s:%d(%s)", p.Host, p.Port, p.SSL)
			portMap[key] = append(portMap[key], val)
		}
		for k := range portMap {
			unique := uniqueStrings(portMap[k])
			sort.Strings(unique)
			portMap[k] = unique
		}
		allPorts = append(allPorts, portMap)
	}

	protocolSet := make(map[string]struct{})
	for _, m := range allPorts {
		for proto := range m {
			protocolSet[proto] = struct{}{}
		}
	}

	for proto := range protocolSet {
		var previous []string
		for i, m := range allPorts {
			ports := m[proto]
			if i == 0 {
				previous = ports
			} else if !reflect.DeepEqual(ports, previous) {
				return true
			}
		}
	}

	for _, m := range allPorts {
		for proto := range protocolSet {
			if _, ok := m[proto]; !ok {
				return true
			}
		}
	}

	return false
}

// ------------------------- 机制间差异 -------------------------
func compareAcrossMechanisms(domain DomainResult) bool {
	var sets []string

	extract := func(r ScoreDetail) string {
		var hosts []string
		for _, p := range r.PortsUsage {
			hosts = append(hosts, fmt.Sprintf("%s:%d(%s)", p.Host, p.Port, p.SSL))
		}
		sort.Strings(hosts)
		return strings.Join(hosts, ";")
	}

	for _, a := range domain.Autodiscover {
		sets = append(sets, extract(a.ScoreDetail))
	}
	for _, a := range domain.Autoconfig {
		sets = append(sets, extract(a.ScoreDetail))
	}
	if domain.SRV.Host != "" {
		sets = append(sets, domain.SRV.Host)
	}
	for _, g := range domain.GUESS {
		sets = append(sets, g)
	}

	unique := uniqueStrings(sets)
	return len(unique) > 1
}
func main() {
	inFile := "init.jsonl"
	outFile := "diff_analysis.jsonl"

	fin, err := os.Open(inFile)
	if err != nil {
		panic(err)
	}
	defer fin.Close()

	fout, err := os.Create(outFile)
	if err != nil {
		panic(err)
	}
	defer fout.Close()

	scanner := bufio.NewScanner(fin)
	writer := bufio.NewWriter(fout)
	defer writer.Flush()

	for scanner.Scan() {
		var domain DomainResult
		if err := json.Unmarshal(scanner.Bytes(), &domain); err != nil {
			fmt.Println("解析失败:", err)
			continue
		}

		internal := make(map[string]bool)
		if len(domain.Autodiscover) > 1 {
			internal["autodiscover"] = comparePortConfigs(domain.Autodiscover)
		}
		if len(domain.Autoconfig) > 1 {
			internal["autoconfig"] = comparePortConfigsAutoconfig(domain.Autoconfig)
		}

		crossDiff := compareAcrossMechanisms(domain)

		result := DiffResult{
			Domain:       domain.Domain,
			InternalDiff: internal,
			CrossDiff:    crossDiff,
		}

		line, _ := json.Marshal(result)
		writer.Write(line)
		writer.Write([]byte("\n"))
	}

	fmt.Println("差异性分析完成，输出文件:", outFile)
}

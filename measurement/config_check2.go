package measurement

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"scan-website/models"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/beevik/etree"
)

// 9.14

// type MethodConfig struct {
// 	Method       string         `json:"Method"`
// 	Protocols    []ProtocolInfo `json:"Protocols"`
// 	OverallCheck string         `json:"OverallCheck"`
// }
// type DomainCheckResult struct {
// 	Domain                   string          `json:"Domain"`
// 	AutodiscoverCheckResult  []*MethodConfig `json:"AutodiscoverCheckResult,omitempty"` //以防有不同path的config不一致的情况，用数组表示
// 	AutoconfigCheckResult    []*MethodConfig `json:"AutoconfigCheckResult,omitempty"`
// 	SRVCheckResult           *MethodConfig   `json:"SRVCheckResult,omitempty"`
// 	AutodiscoverInconsistent bool            `json:"AutodiscoverInconsistent,omitempty"` // 只针对 Autodiscover
// 	AutoconfigInconsistent   bool            `json:"AutoconfigInconsistent,omitempty"`   // 只针对 Autoconfig
// 	Inconsistent             bool            `json:"Inconsistent,omitempty"`             // 记录是否有不一致的情况
// } //9.14

// 尝试保留原配置中的数据结构以供推荐时使用
type PortUsageDetail struct {
	Protocol string `json:"protocol"` // SMTP / IMAP / POP3
	Port     string `json:"port"`
	Status   string `json:"status"` // "secure" / "insecure" / "nonstandard"
	Host     string `json:"host"`   //7.27
	SSL      string `json:"ssl"`    //7.27
}

type DomainCheckDifResult struct {
	Domain                   string                 `json:"domain"`
	AutodiscoverPortUsage    any                    `json:"autodiscover_check_result,omitempty"`
	AutoconfigPortUsage      any                    `json:"autoconfig_check_result,omitempty"`
	SRVPortUsage             any                    `json:"srv_check_result,omitempty"`
	AutodiscoverInconsistent bool                   `json:"autodiscover_inconsistent"`
	AutoconfigInconsistent   bool                   `json:"autoconfig_inconsistent"`
	MechanismDiff            bool                   `json:"mechanism_diff"`
	Inconsistent             bool                   `json:"inconsistent"`
	Extra                    map[string]interface{} `json:"extra,omitempty"` // 保留原始字段
}

// ---- 内部比较：机制内路径差异（协议+端口级别）----
func checkInternalDiff(validResults []map[string]interface{}) bool {
	if len(validResults) == 0 {
		return false
	}

	// 1. 收集所有路径的 ports_usage
	allPorts := []struct {
		Ports []PortUsageDetail
	}{}
	for _, item := range validResults {
		if ports, ok := item["ports_usage"].([]PortUsageDetail); ok {
			allPorts = append(allPorts, struct{ Ports []PortUsageDetail }{Ports: ports})
		}
	}

	// 2. 获取所有协议-端口组合
	protoPortGroups := make(map[string][][]string)
	for idx, item := range allPorts {
		for _, p := range item.Ports {
			key := fmt.Sprintf("%s-%s", strings.ToUpper(p.Protocol), p.Port)
			if _, exists := protoPortGroups[key]; !exists {
				protoPortGroups[key] = make([][]string, len(allPorts))
			}
			entry := fmt.Sprintf("%s:%s (%s)", p.Host, p.Port, strings.ToUpper(p.SSL))
			protoPortGroups[key][idx] = append(protoPortGroups[key][idx], entry)
		}
	}

	// 3. 比较每个协议端口的配置集合是否一致
	diffMap := make(map[string]bool)
	for protoPort, group := range protoPortGroups {
		var setValues []string
		for _, arr := range group {
			sort.Strings(arr)
			setValues = append(setValues, strings.Join(arr, ";"))
		}
		unique := make(map[string]struct{})
		for _, v := range setValues {
			unique[v] = struct{}{}
		}
		if len(unique) > 1 {
			diffMap[protoPort] = true
		}
	}

	// 4. 检查是否有路径缺少某个协议端口
	allKeys := make([]string, 0, len(protoPortGroups))
	for key := range protoPortGroups {
		allKeys = append(allKeys, key)
	}
	for _, item := range allPorts {
		for _, key := range allKeys {
			found := false
			for _, p := range item.Ports {
				k := fmt.Sprintf("%s-%s", strings.ToUpper(p.Protocol), p.Port)
				if k == key {
					found = true
					break
				}
			}
			if !found {
				diffMap[key] = true
			}
		}
	}

	// 5. 返回是否存在任何差异
	for _, v := range diffMap {
		if v {
			return true
		}
	}
	return false
}

// ---- 机制间比较 ----
func comparePortsUsage(autodiscover, autoconfig []map[string]interface{}, srv map[string]interface{}) map[string]map[string]PortUsageDetail {
	comparisonMap := make(map[string]map[string]PortUsageDetail)

	normalize := func(mech string, results []map[string]interface{}) []PortUsageDetail {
		var out []PortUsageDetail
		for _, item := range results {
			if ports, ok := item["ports_usage"].([]PortUsageDetail); ok {
				for _, p := range ports {
					ssl := strings.ToUpper(p.SSL)
					if ssl == "ON" || ssl == "SSL" || ssl == "TLS" {
						ssl = "SSL"
					} else if ssl == "OFF" || ssl == "PLAIN" {
						ssl = "PLAIN"
					}
					out = append(out, PortUsageDetail{
						Protocol: strings.ToUpper(p.Protocol),
						Port:     p.Port,
						Host:     p.Host,
						SSL:      ssl,
					})
				}
			}
		}
		return out
	}

	all := map[string][]PortUsageDetail{
		"autodiscover": normalize("autodiscover", autodiscover),
		"autoconfig":   normalize("autoconfig", autoconfig),
	}

	// SRV
	if srv != nil {
		srvRecords, ok := srv["srv_records"].(map[string]interface{})
		if ok {
			var combined []PortUsageDetail
			for _, typ := range []string{"recv", "send"} {
				if arr, ok := srvRecords[typ].([]interface{}); ok {
					for _, r := range arr {
						rec, _ := r.(map[string]interface{})
						service, _ := rec["Service"].(string)
						target, _ := rec["Target"].(string)
						port := fmt.Sprintf("%v", rec["Port"])

						proto := ""
						ssl := ""
						if strings.Contains(service, "_imaps") {
							proto, ssl = "IMAP", "SSL"
						} else if strings.Contains(service, "_imap") {
							proto, ssl = "IMAP", "STARTTLS"
						} else if strings.Contains(service, "_pop3s") {
							proto, ssl = "POP3", "SSL"
						} else if strings.Contains(service, "_pop3") {
							proto, ssl = "POP3", "STARTTLS"
						} else if strings.Contains(service, "_submission") {
							proto, ssl = "SMTP", "STARTTLS"
						}

						combined = append(combined, PortUsageDetail{
							Protocol: proto,
							Port:     port,
							Host:     strings.TrimSuffix(target, "."),
							SSL:      ssl,
						})
					}
				}
			}
			all["srv"] = combined
		}
	}

	// 组合比较
	for mech, ports := range all {
		for _, item := range ports {
			key := fmt.Sprintf("%s-%s", item.Protocol, item.Port)
			if _, exists := comparisonMap[key]; !exists {
				comparisonMap[key] = make(map[string]PortUsageDetail)
			}
			comparisonMap[key][mech] = item
		}
	}

	return comparisonMap
}

// ---- 机制间/机制内综合分析 ----
func analyzeConsistency(validResults, validacResults []map[string]interface{}, validsrvResult map[string]interface{}) (bool, bool, bool) {
	internalAutoDiff := checkInternalDiff(validResults)
	internalAcDiff := checkInternalDiff(validacResults)

	comparisonMap := comparePortsUsage(validResults, validacResults, validsrvResult)

	mechDiff := false
	for _, mechData := range comparisonMap {
		fields := []string{"Host", "SSL"}
		for _, field := range fields {
			values := []string{}
			for _, v := range mechData {
				switch field {
				case "Host":
					values = append(values, v.Host)
				case "SSL":
					values = append(values, v.SSL)
				}
			}
			if len(values) > 1 {
				allEqual := true
				for i := 1; i < len(values); i++ {
					if values[i] != values[0] {
						allEqual = false
						break
					}
				}
				if !allEqual {
					mechDiff = true
					break
				}
			}
		}
		if mechDiff {
			break
		}
	}

	return internalAutoDiff, internalAcDiff, mechDiff
}

func processDomainResult2(obj models.DomainResult) *DomainCheckDifResult {
	domain := obj.Domain
	var autodiscoverConfigs []*models.MethodConfig
	var autoconfigConfigs []*models.MethodConfig
	var srvConfig *models.MethodConfig

	// 遍历 Autodiscover 配置
	var validResults []map[string]interface{}
	for _, entry := range obj.Autodiscover {
		if entry.Config != "" && !strings.HasPrefix(entry.Config, "Bad") && !strings.HasPrefix(entry.Config, "Errorcode") && !strings.HasPrefix(entry.Config, "Non-valid") {
			r, _ := parseXMLConfig_Autodiscover(entry.Config)

			if r != nil {
				autodiscoverConfigs = append(autodiscoverConfigs, r)
			}

			PortsUsage := calculatePort_Autodiscover(entry.Config)
			validResults = append(validResults, map[string]interface{}{
				"index":       entry.Index,
				"uri":         entry.URI,
				"method":      entry.Method,
				"config":      entry.Config,
				"ports_usage": PortsUsage,
				"redirects":   entry.Redirects,
				"cert_info":   entry.CertInfo,
			})
		}
	}

	// 遍历 Autoconfig 配置
	var validacResults []map[string]interface{}
	for _, entry := range obj.Autoconfig {
		if entry.Config != "" {
			s, _ := parseXMLConfig_Autoconfig(entry.Config)
			if s != nil {
				autoconfigConfigs = append(autoconfigConfigs, s)
			}
			PortsUsage := calculatePort_Autoconfig(entry.Config)
			validacResults = append(validacResults, map[string]interface{}{
				"index":       entry.Index,
				"uri":         entry.URI,
				"method":      entry.Method,
				"config":      entry.Config,
				"ports_usage": PortsUsage,
				"redirects":   entry.Redirects,
				"cert_info":   entry.CertInfo,
			})
		}
	}

	// 解析 SRV 记录
	var validsrvResult map[string]interface{}
	if obj.SRV.RecvRecords != nil || obj.SRV.SendRecords != nil {
		srvConfig, _ = parseConfig_SRV(&obj.SRV)
		srvPortsUsage := calculate_SRV(obj.SRV)
		validsrvResult = map[string]interface{}{
			"srv_records": map[string]interface{}{
				"recv": obj.SRV.RecvRecords,
				"send": obj.SRV.SendRecords,
			},
			"dns_record":  obj.SRV.DNSRecord,
			"ports_usage": srvPortsUsage,
		}
	}

	// 判断是否所有结果都为空
	if len(autodiscoverConfigs) == 0 && len(autoconfigConfigs) == 0 && srvConfig == nil {
		return nil
	}

	//比较所有字段
	// // 比较 Autodiscover 结果
	// autodiscoverConsistent, finalAutodiscover := compareMethodConfigs(autodiscoverConfigs)
	// // 比较 Autoconfig 结果
	// autoconfigConsistent, finalAutoconfig := compareMethodConfigs(autoconfigConfigs)

	//比较关键字段
	// autodiscoverConsistent, finalAutodiscover := compareMethodConfigs_autodiscover(autodiscoverConfigs)
	// autoconfigConsistent, finalAutoconfig := compareMethodConfigs_autoconfig(autoconfigConfigs)
	internalAdDiff, internalAcDiff, mechDiff := analyzeConsistency(validResults, validacResults, validsrvResult)
	// 总体不一致标志 = 任一机制内不一致 或 机制间不一致
	inconsistent := internalAdDiff || internalAcDiff || mechDiff

	// 记录最终结果
	data := &DomainCheckDifResult{
		Domain:                   domain,
		AutodiscoverPortUsage:    validResults,
		AutoconfigPortUsage:      validacResults,
		SRVPortUsage:             validsrvResult,
		AutodiscoverInconsistent: internalAdDiff,
		AutoconfigInconsistent:   internalAcDiff,
		MechanismDiff:            mechDiff,
		Inconsistent:             inconsistent,
	}

	// // 记录不一致的情况
	// if data.Inconsistent {
	// 	fmt.Printf("Inconsistent Config for Domain: %s\n", domain)
	// }

	return data
}

// 从 init.jsonl 中读取每行域名结果，分析机制内外差异并保存
func CheckDifferences() {
	inputFile := "/home/wzq/scan-website/cmd/init.jsonl"
	outputFile := "/home/wzq/scan-website/cmd/check_dif_results.jsonl"

	file, err := os.Open(inputFile)
	if err != nil {
		log.Fatalf("❌ Failed to open input file: %v", err)
	}
	defer file.Close()

	reader := bufio.NewReader(file)
	sem := make(chan struct{}, 10) // 控制并发数
	var id int64
	var wg sync.WaitGroup

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Printf("⚠️  Error reading line: %v", err)
			continue
		}

		var obj models.DomainResult
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			log.Printf("⚠️  Skipping invalid JSON line: %v", err)
			continue
		}

		sem <- struct{}{}
		wg.Add(1)
		go func(obj models.DomainResult) {
			defer wg.Done()
			defer func() { <-sem }()

			data := processDomainResult2(obj)
			curID := atomic.AddInt64(&id, 1)
			fmt.Printf("[%d] Processed domain: %s\n", curID, obj.Domain)

			if data != nil {
				if err := saveCheckDifResultAsJSONL(data, outputFile); err != nil {
					log.Printf("❌ Error saving result for %s: %v", obj.Domain, err)
				}
			}
		}(obj)
	}

	wg.Wait()
	fmt.Println("✅ All domains processed and saved.")
}

// 将差异分析结果写入 JSONL 文件
func saveCheckDifResultAsJSONL(result *DomainCheckDifResult, outputFile string) error {
	if result == nil {
		return fmt.Errorf("nil result")
	}

	jsonData, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("marshal error: %v", err)
	}

	file, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("open file error: %v", err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	if _, err := writer.Write(jsonData); err != nil {
		return fmt.Errorf("write error: %v", err)
	}
	if _, err := writer.Write([]byte("\n")); err != nil {
		return fmt.Errorf("newline write error: %v", err)
	}
	writer.Flush()

	return nil
}

func calculatePort_Autodiscover(config string) []PortUsageDetail {
	doc := etree.NewDocument()
	if err := doc.ReadFromString(config); err != nil {
		return nil
	}
	//这里是评分规则
	root := doc.SelectElement("Autodiscover")
	if root == nil {

		return nil
	}
	responseElem := root.SelectElement("Response")
	if responseElem == nil {

		return nil
	}
	accountElem := responseElem.SelectElement("Account")
	if accountElem == nil {
		return nil
	}
	accountTypeElem := accountElem.SelectElement("AccountType")
	if accountTypeElem == nil || accountTypeElem.Text() != "email" {
		return nil
	}
	actionElem := accountElem.SelectElement("Action")
	if actionElem == nil || actionElem.Text() != "settings" {
		return nil
	}

	var portsUsage []PortUsageDetail
	// 记录使用的端口情况
	securePorts := map[string]bool{
		"SMTP": false,
		"IMAP": false,
		"POP3": false,
	}
	insecurePorts := map[string]bool{
		"SMTP": false,
		"IMAP": false,
		"POP3": false,
	}
	nonStandardPorts := map[string]bool{
		"SMTP": false,
		"IMAP": false,
		"POP3": false,
	}
	//var protocols []ProtocolInfo
	for _, protocolElem := range accountElem.SelectElements("Protocol") {
		//protocol := ProtocolInfo{}
		protocolType := ""
		port := ""
		host := ""
		ssl := ""
		// 检查每个子元素是否存在再获取其内容
		if typeElem := protocolElem.SelectElement("Type"); typeElem != nil {
			protocolType = typeElem.Text()
		}
		if serverElem := protocolElem.SelectElement("Server"); serverElem != nil {
			host = serverElem.Text() //7.27
		}
		if portElem := protocolElem.SelectElement("Port"); portElem != nil {
			port = portElem.Text()
		}
		if encElem := protocolElem.SelectElement("Encryption"); encElem != nil {
			ssl = encElem.Text()
		} else if sslElem := protocolElem.SelectElement("SSL"); sslElem != nil {
			ssl = sslElem.Text()
		} else {
			ssl = "N/A"
		} //7.27
		// if protocol.SSL != "SSL" {
		// 	scores["SSL"] = "HHH"
		// 	//return scores
		// }
		// if protocol.Type == "SMTP" && protocol.Port == "465" {
		// 	scores["SMTPS"] = "yes"
		// }
		// if protocol.Type == "IMAP" && protocol.Port == "993" {
		// 	scores["IMAPS"] = "yes"
		// }
		status := "nonstandard"

		//9.15_5
		if encElem := protocolElem.SelectElement("Encryption"); encElem != nil {
			switch ssl {
			case "NONE":
				status = "standard"
			case "SSL":
				status = "standard"
			case "TLS":
				status = "standard"
			case "Auto":
				status = "standard"
			default:
				status = "nonstandard"
			}

		} else if sslElem := protocolElem.SelectElement("SSL"); sslElem != nil {
			switch ssl {
			case "on":
				status = "standard"
			case "off":
				status = "standard"
			default:
				status = "nonstandard"
			}
		}
		// 分类端口
		switch protocolType {
		case "SMTP":
			if port == "465" {
				// status = "secure" //9.15_5
				securePorts["SMTP"] = true
			} else if port == "25" || port == "587" {
				//status = "insecure"
				insecurePorts["SMTP"] = true
			} else {
				nonStandardPorts["SMTP"] = true
			}
		case "IMAP":
			if port == "993" {
				//status = "secure"
				securePorts["IMAP"] = true
			} else if port == "143" {
				//status = "insecure"
				insecurePorts["IMAP"] = true
			} else {
				nonStandardPorts["IMAP"] = true
			}
		case "POP3":
			if port == "995" {
				//status = "secure"
				securePorts["POP3"] = true
			} else if port == "110" {
				//status = "insecure"
				insecurePorts["POP3"] = true
			} else {
				nonStandardPorts["POP3"] = true
			}
		}
		if protocolType != "" && port != "" {
			portsUsage = append(portsUsage, PortUsageDetail{
				Protocol: protocolType,
				Port:     port,
				Status:   status,
				Host:     host,
				SSL:      ssl,
			})
		} //全部记录到新增结构中
	}

	return portsUsage
}

func calculatePort_Autoconfig(config string) []PortUsageDetail {
	doc := etree.NewDocument()
	if err := doc.ReadFromString(config); err != nil {
		return nil
	}
	//这里是评分规则
	root := doc.SelectElement("clientConfig")
	if root == nil {
		return nil
	}
	emailProviderElem := root.SelectElement("emailProvider")
	if emailProviderElem == nil {
		return nil
	}
	var portsUsage []PortUsageDetail
	// 记录使用的端口情况
	securePorts := map[string]bool{
		"SMTP": false,
		"IMAP": false,
		"POP3": false,
	}
	insecurePorts := map[string]bool{
		"SMTP": false,
		"IMAP": false,
		"POP3": false,
	}
	nonStandardPorts := map[string]bool{
		"SMTP": false,
		"IMAP": false,
		"POP3": false,
	}
	//var protocols []ProtocolInfo
	for _, protocolElem := range emailProviderElem.SelectElements("incomingServer") {
		//protocol := ProtocolInfo{}
		protocolType := ""
		port := ""
		host := ""
		ssl := ""
		// 检查每个子元素是否存在再获取其内容
		if typeELem := protocolElem.SelectAttr("type"); typeELem != nil {
			protocolType = typeELem.Value //? type属性 -> <Type>
		}
		if serverElem := protocolElem.SelectElement("hostname"); serverElem != nil {
			host = serverElem.Text() //<hostname> -> <Server>
		}
		if portElem := protocolElem.SelectElement("port"); portElem != nil {
			port = portElem.Text()
		}
		if sslElem := protocolElem.SelectElement("socketType"); sslElem != nil {
			ssl = sslElem.Text()
		} else {
			ssl = "N/A"
		} //7.27
		status := "nonstandard"
		//9.15_5
		switch ssl {
		case "SSL":
			status = "standard"
		case "PLAIN":
			status = "standard"
		case "STARTTLS":
			status = "standard"
		default:
			status = "nonstandard"
		}
		// 分类端口
		switch protocolType {
		case "smtp":
			if port == "465" {
				//status = "secure"
				securePorts["SMTP"] = true
			} else if port == "25" || port == "587" {
				//status = "insecure"
				insecurePorts["SMTP"] = true
			} else {
				nonStandardPorts["SMTP"] = true
			}
		case "imap":
			if port == "993" {
				//status = "secure"
				securePorts["IMAP"] = true
			} else if port == "143" {
				//status = "insecure"
				insecurePorts["IMAP"] = true
			} else {
				nonStandardPorts["IMAP"] = true
			}
		case "pop3":
			if port == "995" {
				//status = "secure"
				securePorts["POP3"] = true
			} else if port == "110" {
				//status = "insecure"
				insecurePorts["POP3"] = true
			} else {
				nonStandardPorts["POP3"] = true
			}
		}
		if protocolType != "" && port != "" {
			portsUsage = append(portsUsage, PortUsageDetail{
				Protocol: strings.ToTitle(protocolType),
				Port:     port,
				Status:   status,
				Host:     host,
				SSL:      ssl,
			})
		} //全部记录到新增结构中
	}

	for _, protocolElem := range emailProviderElem.SelectElements("outgoingServer") {
		//protocol := ProtocolInfo{}
		protocolType := ""
		port := ""
		host := ""
		ssl := ""
		// 检查每个子元素是否存在再获取其内容
		if typeELem := protocolElem.SelectAttr("type"); typeELem != nil {
			protocolType = typeELem.Value //? type属性 -> <Type>
		}
		if serverElem := protocolElem.SelectElement("hostname"); serverElem != nil {
			host = serverElem.Text() //<hostname> -> <Server>
		}
		if portElem := protocolElem.SelectElement("port"); portElem != nil {
			port = portElem.Text()
		}
		if sslElem := protocolElem.SelectElement("socketType"); sslElem != nil {
			ssl = sslElem.Text()
		} else {
			ssl = "N/A"
		}
		status := "nonstandard"
		//9.15_5
		switch ssl {
		case "SSL":
			status = "standard"
		case "PLAIN":
			status = "standard"
		case "STARTTLS":
			status = "standard"
		default:
			status = "nonstandard"
		}
		// 分类端口
		switch protocolType {
		case "smtp":
			if port == "465" {
				//status = "secure"
				securePorts["SMTP"] = true
			} else if port == "25" || port == "587" {
				//status = "insecure"
				insecurePorts["SMTP"] = true
			} else {
				nonStandardPorts["SMTP"] = true
			}
		case "imap":
			if port == "993" {
				//status = "secure"
				securePorts["IMAP"] = true
			} else if port == "143" {
				//status = "insecure"
				insecurePorts["IMAP"] = true
			} else {
				nonStandardPorts["IMAP"] = true
			}
		case "pop3":
			if port == "995" {
				//status = "secure"
				securePorts["POP3"] = true
			} else if port == "110" {
				//status = "insecure"
				insecurePorts["POP3"] = true
			} else {
				nonStandardPorts["POP3"] = true
			}
		}
		if protocolType != "" && port != "" {
			portsUsage = append(portsUsage, PortUsageDetail{
				Protocol: strings.ToTitle(protocolType),
				Port:     port,
				Status:   status,
				Host:     host,
				SSL:      ssl,
			})
		} //全部记录到新增结构中
	}

	return portsUsage
}

func calculate_SRV(result models.SRVResult) []PortUsageDetail {
	securePorts := map[string]bool{}
	insecurePorts := map[string]bool{}
	nonStandardPorts := map[string]bool{}

	standardEncrypted := map[uint16]bool{993: true, 995: true, 465: true}
	standardInsecure := map[uint16]bool{143: true, 110: true, 25: true, 587: true}
	var portsUsage []PortUsageDetail
	allRecords := append(result.RecvRecords, result.SendRecords...)
	for _, record := range allRecords {
		port := record.Port
		status := Identify_Port_Status(record)
		fmt.Print(status)
		if standardEncrypted[port] {
			securePorts[record.Service] = true
		} else if standardInsecure[port] {
			insecurePorts[record.Service] = true
		} else {
			nonStandardPorts[record.Service] = true
		}
		portsUsage = append(portsUsage, PortUsageDetail{
			Protocol: normalizeProtocol(record.Service),
			Port:     strconv.Itoa(int(port)),
			Status:   status,
			Host:     strings.TrimSuffix(record.Target, "."),
			SSL:      normalizeSSL(record.Service), //9.15_2
		})
	}

	fmt.Print(portsUsage)
	return portsUsage
}
func Identify_Port_Status(record models.SRVRecord) string {
	port := record.Port
	service_prefix := strings.Split(record.Service, ".")[0]
	var status string
	switch service_prefix {
	case "_submissions":
		if port == 465 {
			status = "secure"
		} else {
			status = "nonstandard"
		}
	case "_submission":
		if port == 25 || port == 587 {
			status = "insecure"
		} else {
			status = "nonstandard"
		}
	case "_imaps":
		if port == 993 {
			status = "secure"
		} else {
			status = "nonstandard"
		}
	case "_imap":
		if port == 143 {
			status = "insecure"
		} else {
			status = "nonstandard"
		}
	case "_pop3s":
		if port == 995 {
			status = "secure"
		} else {
			status = "nonstandard"
		}
	case "_pop3":
		if port == 110 {
			status = "insecure"
		} else {
			status = "nonstandard"
		}
	}
	return status
}
func normalizeProtocol(service string) string {
	if strings.HasPrefix(service, "_submission") || strings.HasPrefix(service, "_submissions") {
		return "SMTP"
	} else if strings.HasPrefix(service, "_imap") || strings.HasPrefix(service, "_imaps") {
		return "IMAP"
	} else if strings.HasPrefix(service, "_pop3") || strings.HasPrefix(service, "_pop3s") {
		return "POP3"
	}
	return "OTHER"
}
func normalizeSSL(service string) string {
	if strings.HasPrefix(service, "_submissions") || strings.HasPrefix(service, "_imaps") || strings.HasPrefix(service, "_pop3s") {
		return "on"
	} else if strings.HasPrefix(service, "_submission") || strings.HasPrefix(service, "_imap") || strings.HasPrefix(service, "_pop3") {
		return "off"
	}
	return "UNKNOWN"
}

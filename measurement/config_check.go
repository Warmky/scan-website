package measurement

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"scan-website/models"
	"sort"
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

func processDomainResult(obj models.DomainResult) *models.DomainCheckResult {
	domain := obj.Domain
	var autodiscoverConfigs []*models.MethodConfig
	var autoconfigConfigs []*models.MethodConfig
	var srvConfig *models.MethodConfig

	// 遍历 Autodiscover 配置
	for _, entry := range obj.Autodiscover {
		if entry.Config != "" && !strings.HasPrefix(entry.Config, "Bad") && !strings.HasPrefix(entry.Config, "Errorcode") && !strings.HasPrefix(entry.Config, "Non-valid") {
			r, _ := parseXMLConfig_Autodiscover(entry.Config)
			if r != nil {
				autodiscoverConfigs = append(autodiscoverConfigs, r)
			}
		}
	}

	// 遍历 Autoconfig 配置
	for _, entry := range obj.Autoconfig {
		if entry.Config != "" {
			s, _ := parseXMLConfig_Autoconfig(entry.Config)
			if s != nil {
				autoconfigConfigs = append(autoconfigConfigs, s)
			}
		}
	}

	// 解析 SRV 记录
	if obj.SRV.RecvRecords != nil || obj.SRV.SendRecords != nil {
		srvConfig, _ = parseConfig_SRV(&obj.SRV)
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
	autodiscoverConsistent, finalAutodiscover := compareMethodConfigs_autodiscover(autodiscoverConfigs)
	autoconfigConsistent, finalAutoconfig := compareMethodConfigs_autoconfig(autoconfigConfigs)

	// 记录最终结果
	data := &models.DomainCheckResult{
		Domain:                   domain,
		AutodiscoverCheckResult:  finalAutodiscover,
		AutoconfigCheckResult:    finalAutoconfig,
		SRVCheckResult:           srvConfig,
		AutodiscoverInconsistent: !autodiscoverConsistent,
		AutoconfigInconsistent:   !autoconfigConsistent,
		Inconsistent:             !autodiscoverConsistent || !autoconfigConsistent,
	}

	// // 记录不一致的情况
	// if data.Inconsistent {
	// 	fmt.Printf("Inconsistent Config for Domain: %s\n", domain)
	// }

	return data
}

func compareMethodConfigs(configs []*models.MethodConfig) (bool, []*models.MethodConfig) {
	if len(configs) == 0 {
		return true, nil
	}

	// 用 map 进行去重
	uniqueConfigs := make(map[string]*models.MethodConfig)
	for _, cfg := range configs {
		if cfg != nil {
			// key := generateProtocolKey(cfg.Protocols)//3.26 原来是按照关键字段排序，但是所有字段都参与比较
			key := generateProtocolKey(cfg.Protocols) //3.26 改成只比较关键字段
			uniqueConfigs[key] = cfg
		}
	}

	// 转换回数组
	var finalConfigs []*models.MethodConfig
	for _, v := range uniqueConfigs {
		finalConfigs = append(finalConfigs, v)
	}

	// 如果只有一种 `Protocols` 组合，则认为一致
	if len(finalConfigs) == 1 {
		return true, finalConfigs
	}

	// 否则，返回所有不同的 `Protocols`
	return false, finalConfigs
}

func compareMethodConfigs_autodiscover(configs []*models.MethodConfig) (bool, []*models.MethodConfig) {
	if len(configs) == 0 {
		return true, nil
	}

	// 用 map 进行去重
	uniqueConfigs := make(map[string]*models.MethodConfig)
	for _, cfg := range configs {
		if cfg != nil {
			key := generateProtocolKey_autodiscover(cfg.Protocols) //3.26 改成只比较关键字段(onlysome)
			uniqueConfigs[key] = cfg
		}
	}

	// 转换回数组
	var finalConfigs []*models.MethodConfig
	for _, v := range uniqueConfigs {
		finalConfigs = append(finalConfigs, v)
	}

	// 如果只有一种 `Protocols` 组合，则认为一致
	if len(finalConfigs) == 1 {
		fmt.Println("Only one Protocols:")
		for i, cfg := range finalConfigs {
			fmt.Printf("  Config %d:\n", i+1)
			for _, proto := range cfg.Protocols {
				fmt.Printf("    Type: %s, Server: %s, Port: %s, SSL: %s\n",
					proto.Type, proto.Server, proto.Port, proto.SSL)
			}
		}
		return true, finalConfigs
	}

	fmt.Println("Has different Protocols:")
	for i, cfg := range finalConfigs {
		fmt.Printf("  Config %d:\n", i+1)
		for _, proto := range cfg.Protocols {
			fmt.Printf("    Type: %s, Server: %s, Port: %s, SSL: %s\n",
				proto.Type, proto.Server, proto.Port, proto.SSL)
		}
	}
	// 否则，返回所有不同的 `Protocols`
	return false, finalConfigs
}

func compareMethodConfigs_autoconfig(configs []*models.MethodConfig) (bool, []*models.MethodConfig) {
	if len(configs) == 0 {
		return true, nil
	}

	// 用 map 进行去重
	uniqueConfigs := make(map[string]*models.MethodConfig)
	for _, cfg := range configs {
		if cfg != nil {
			key := generateProtocolKey_autoconfig(cfg.Protocols) //3.26 改成只比较关键字段
			uniqueConfigs[key] = cfg
		}
	}

	// 转换回数组
	var finalConfigs []*models.MethodConfig
	for _, v := range uniqueConfigs {
		finalConfigs = append(finalConfigs, v)
	}

	// 如果只有一种 `Protocols` 组合，则认为一致
	if len(finalConfigs) == 1 {
		return true, finalConfigs
	}

	// 否则，返回所有不同的 `Protocols`
	return false, finalConfigs
}

// 生成 `Protocols` 的唯一 Key（用于比较） //比较所有字段
func generateProtocolKey(protocols []models.ProtocolInfo) string {
	if len(protocols) == 0 {
		return ""
	}

	// 确保 `Protocols` 排序一致，避免相同配置因顺序不同而被误判
	sort.SliceStable(protocols, func(i, j int) bool {
		if protocols[i].Type != protocols[j].Type {
			return protocols[i].Type < protocols[j].Type
		}
		if protocols[i].Server != protocols[j].Server {
			return protocols[i].Server < protocols[j].Server
		}
		if protocols[i].Port != protocols[j].Port {
			return protocols[i].Port < protocols[j].Port
		}
		if protocols[i].SSL != protocols[j].SSL {
			return protocols[i].SSL < protocols[j].SSL
		}
		return protocols[i].Encryption < protocols[j].Encryption
	})

	// 序列化成 JSON 作为唯一 key
	b, _ := json.Marshal(protocols)
	return string(b)
}

// 只比较关键字段
func generateProtocolKey_autodiscover(protocols []models.ProtocolInfo) string { //3.26 只比较关键字段
	if len(protocols) == 0 {
		return ""
	}

	// 确保 `Protocols` 排序一致，避免相同配置因顺序不同而被误判
	sort.SliceStable(protocols, func(i, j int) bool {
		if protocols[i].Type != protocols[j].Type {
			return protocols[i].Type < protocols[j].Type
		}
		if protocols[i].Server != protocols[j].Server {
			return protocols[i].Server < protocols[j].Server
		}
		if protocols[i].Port != protocols[j].Port {
			return protocols[i].Port < protocols[j].Port
		}
		if protocols[i].Encryption != protocols[j].Encryption {
			return protocols[i].Encryption < protocols[j].Encryption
		}
		return protocols[i].SSL < protocols[j].SSL
	})

	// 只保留用于比较的字段
	var keyProtocols []struct {
		Type       string `json:"Type"`
		Server     string `json:"Server"`
		Port       string `json:"Port"`
		Encryption string `json:"Encryption"`
		SSL        string `json:"SSL"`
	}

	for _, p := range protocols {
		keyProtocols = append(keyProtocols, struct {
			Type       string `json:"Type"`
			Server     string `json:"Server"`
			Port       string `json:"Port"`
			Encryption string `json:"Encryption"`
			SSL        string `json:"SSL"`
		}{
			Type:       p.Type,
			Server:     p.Server,
			Port:       p.Port,
			Encryption: p.Encryption,
			SSL:        p.SSL,
		})
	}

	// 序列化成 JSON 作为唯一 key
	b, _ := json.Marshal(keyProtocols)
	return string(b)
}
func generateProtocolKey_autoconfig(protocols []models.ProtocolInfo) string { //3.26 只比较关键字段
	if len(protocols) == 0 {
		return ""
	}

	// 确保 `Protocols` 排序一致，避免相同配置因顺序不同而被误判
	sort.SliceStable(protocols, func(i, j int) bool {
		if protocols[i].Type != protocols[j].Type {
			return protocols[i].Type < protocols[j].Type
		}
		if protocols[i].Server != protocols[j].Server {
			return protocols[i].Server < protocols[j].Server
		}
		if protocols[i].Port != protocols[j].Port {
			return protocols[i].Port < protocols[j].Port
		}
		return protocols[i].SSL < protocols[j].SSL
	})

	// 只保留用于比较的字段
	var keyProtocols []struct {
		Type   string `json:"Type"`
		Server string `json:"Server"`
		Port   string `json:"Port"`
		SSL    string `json:"SSL"`
	}

	for _, p := range protocols {
		keyProtocols = append(keyProtocols, struct {
			Type   string `json:"Type"`
			Server string `json:"Server"`
			Port   string `json:"Port"`
			SSL    string `json:"SSL"`
		}{
			Type:   p.Type,
			Server: p.Server,
			Port:   p.Port,
			SSL:    p.SSL,
		})
	}

	// 序列化成 JSON 作为唯一 key
	b, _ := json.Marshal(keyProtocols)
	return string(b)
}

// 解析每个对象中的Autodiscover的config
func parseXMLConfig_Autodiscover(config string) (*models.MethodConfig, error) {
	// 创建一个新的 etree 文档
	doc := etree.NewDocument()

	// 解析 config 中的 XML 字符串
	err := doc.ReadFromString(config)
	if err != nil {
		log.Printf("Error parsing XML: %v", err)
		return nil, err
	}

	// 查找根元素
	root := doc.SelectElement("Autodiscover")
	if root == nil {
		log.Println("No root element <Autodiscover> found.")
		result1 := &models.MethodConfig{
			Method:       "Autodiscover",
			Protocols:    nil,
			OverallCheck: "Invalid, root element <Autodiscover> lost",
		}
		return result1, fmt.Errorf("missing root element <Autodiscover>")
	}

	// 查找 Response 元素
	responseElem := root.SelectElement("Response")
	if responseElem == nil {
		log.Println("No <Response> element found.")
		result2 := &models.MethodConfig{
			Method:       "Autodiscover",
			Protocols:    nil,
			OverallCheck: "Invalid, <Response> element lost",
		}
		return result2, fmt.Errorf("missing <Response> element")
	}

	// // 打印 User 和 Account 信息
	// userElem := responseElem.SelectElement("User")
	// if userElem == nil {
	// 	result3 := &MethodConfig{
	// 		Method:       "Autodiscover",
	// 		Protocols:    nil,
	// 		OverallCheck: "Invalid, <User> element lost",
	// 	}
	// 	return result3, fmt.Errorf("missing <User> element")
	// } else if userElem.SelectElement("DisplayName") == nil {
	// 	result3 := &MethodConfig{
	// 		Method:       "Autodiscover",
	// 		Protocols:    nil,
	// 		OverallCheck: "Invalid,missing <DisplayName> in <User>",
	// 	}
	// 	return result3, fmt.Errorf("missing <DisplayName> in <User>")
	// } //需要考虑将diaplayName输出到结构体中吗？TODO  3.8因为没有User的过多，先不算作错误10105 ，9

	accountElem := responseElem.SelectElement("Account")
	if accountElem == nil {
		result4 := &models.MethodConfig{
			Method:       "Autodiscover",
			Protocols:    nil,
			OverallCheck: "Invalid, missing <Account> element",
		}
		return result4, fmt.Errorf("missing <Account> element")
	}
	//4.1检查<AccountType>和<Action>
	accountTypeElem := accountElem.SelectElement("AccountType")
	if accountTypeElem == nil || accountTypeElem.Text() != "email" {
		return &models.MethodConfig{
			Method:       "Autodiscover",
			Protocols:    nil,
			OverallCheck: "Invalid, <AccountType> must be 'email'",
		}, fmt.Errorf("<AccountType> must be 'email'")
	}
	actionElem := accountElem.SelectElement("Action")
	if actionElem == nil || actionElem.Text() != "settings" {
		return &models.MethodConfig{
			Method:       "Autodiscover",
			Protocols:    nil,
			OverallCheck: "Invalid, <Action> must be 'settings'",
		}, fmt.Errorf("<Action> must be 'settings'")
	}
	//4.2查找<Protocol>元素
	var protocols []models.ProtocolInfo
	for _, protocolElem := range accountElem.SelectElements("Protocol") {
		protocol := models.ProtocolInfo{}
		protocol.SingleCheck = "Valid" //首先设置为Valid //
		// 检查每个子元素是否存在再获取其内容
		if typeElem := protocolElem.SelectElement("Type"); typeElem != nil {
			protocol.Type = typeElem.Text()
		}
		if serverElem := protocolElem.SelectElement("Server"); serverElem != nil {
			protocol.Server = serverElem.Text()
		}
		if portElem := protocolElem.SelectElement("Port"); portElem != nil {
			protocol.Port = portElem.Text()
		}
		if domainRequiredElem := protocolElem.SelectElement("DomainRequired"); domainRequiredElem != nil {
			protocol.DomainRequired = domainRequiredElem.Text()
		}
		if spaElem := protocolElem.SelectElement("SPA"); spaElem != nil {
			protocol.SPA = spaElem.Text()
		}
		if sslElem := protocolElem.SelectElement("SSL"); sslElem != nil {
			protocol.SSL = sslElem.Text()
		}
		if authRequiredElem := protocolElem.SelectElement("AuthRequired"); authRequiredElem != nil {
			protocol.AuthRequired = authRequiredElem.Text()
		}
		if encryptionElem := protocolElem.SelectElement("Encryption"); encryptionElem != nil {
			protocol.Encryption = encryptionElem.Text()
		}
		if usePOPAuthElem := protocolElem.SelectElement("UsePOPAuth"); usePOPAuthElem != nil {
			protocol.UsePOPAuth = usePOPAuthElem.Text()
		}
		if smtpLastElem := protocolElem.SelectElement("SMTPLast"); smtpLastElem != nil {
			protocol.SMTPLast = smtpLastElem.Text()
		}
		if ttlElem := protocolElem.SelectElement("TTL"); ttlElem != nil {
			protocol.TTL = ttlElem.Text()
		}

		// 检查
		if protocolElem.SelectAttr("Type") != nil && protocol.Type != "" {
			protocol.SingleCheck = fmt.Sprintf("Invalid, <Type> element mustn't show, Type attribute of <Protocol> is %s", protocolElem.SelectAttr("Type").Value)
		} else {
			if protocol.Type == "" && protocolElem.SelectAttr("Type") == nil {
				protocol.SingleCheck = "Invalid, no Type attribute in <Protocol> element nor <Type> element"
			}
		}
		if protocol.SSL == "" {
			protocol.SSL = "default(on)" //补充了SSL的缺省值
		} //SSL检查应该在Encryption之前
		if protocol.Encryption != "" {
			if !(protocol.Type == "IMAP" || protocol.Type == "SMTP" || protocol.Type == "POP3") {
				protocol.SingleCheck = "Invalid, supposed no <Encryption>"
			}
			if !(protocol.Encryption == "None" || protocol.Encryption == "SSL" || protocol.Encryption == "TLS" || protocol.Encryption == "Auto") { //按照协议规范是只有这4个值，实际上不止，还有如STARTTLS
				protocol.SingleCheck = fmt.Sprintf("Invalid, Encryption method %s, not supposed to appear", protocol.Encryption)
			}
			if protocol.SSL != "" {
				protocol.SSL = ""
			}
		}
		if protocol.Type == "EXCH" || protocol.Type == "EXPR" || protocol.Type == "EXHTTP" || protocol.Type == "POP3" || protocol.Type == "SMTP" || protocol.Type == "IMAP" {
			if protocol.Server == "" {
				protocol.SingleCheck = "Invalid, no valid Server"
			}
		}
		if protocol.SMTPLast != "" && protocol.Type != "SMTP" {
			protocol.SMTPLast = ""
			protocol.SingleCheck = "Invalid, SMTPLast not supposed"
		}
		if protocol.SPA == "" && (protocol.Type == "IMAP" || protocol.Type == "SMTP" || protocol.Type == "POP3") {
			protocol.SPA = "default(on)" //补充SPA缺省值
		}
		if protocol.SPA != "" && !(protocol.Type == "IMAP" || protocol.Type == "SMTP" || protocol.Type == "POP3") {
			protocol.SPA = ""
			protocol.SingleCheck = "Invalid, SPA not supposed"
		}
		if protocol.UsePOPAuth != "" && protocol.Type != "SMTP" {
			protocol.UsePOPAuth = ""
			protocol.SingleCheck = "Invalid, UsePOPAuth not supposed"
		}

		protocols = append(protocols, protocol)
	}
	finalStatus := "Valid"
	for _, protocol := range protocols {
		if protocol.SingleCheck != "Valid" {
			finalStatus = "Invalid"
			break
		}
	} //Autodiscover采取的是有一个协议不对就都不对（因为没有找到优先使用规则）
	result := &models.MethodConfig{
		Method:       "Autodiscover",
		Protocols:    protocols,
		OverallCheck: finalStatus,
	}
	return result, nil

}

// 解析每个对象中的Autoconfig的config
func parseXMLConfig_Autoconfig(config string) (*models.MethodConfig, error) {
	doc := etree.NewDocument()
	err := doc.ReadFromString(config)
	if err != nil {
		log.Printf("Error parsing XML: %v", err)
		return nil, err
	}
	//1.确保根元素是<ClientConfig>
	root := doc.SelectElement("clientConfig")
	if root == nil {
		result1 := &models.MethodConfig{
			Method:       "Autoconfig",
			Protocols:    nil,
			OverallCheck: "Invalid, root element <clientConfig> lost",
		}
		return result1, fmt.Errorf("missing root element <clientConfig>")
	}
	//2.查找<emailProvider>元素
	emailProviderElem := root.SelectElement("emailProvider")
	if emailProviderElem == nil {
		result2 := &models.MethodConfig{
			Method:       "Autoconfig",
			Protocols:    nil,
			OverallCheck: "Invalid, <emailProvider> element lost",
		}
		return result2, fmt.Errorf("missing <emailProvider> element")
	}
	//先查找incomingServer,再OutgoingServer
	var protocols []models.ProtocolInfo
	for _, protocolElem := range emailProviderElem.SelectElements("incomingServer") {
		protocol := models.ProtocolInfo{}
		protocol.SingleCheck = "Valid"
		if typeELem := protocolElem.SelectAttr("type"); typeELem != nil {
			protocol.Type = typeELem.Value //? type属性 -> <Type>
		}
		if serverElem := protocolElem.SelectElement("hostname"); serverElem != nil {
			protocol.Server = serverElem.Text() //<hostname> -> <Server>
		}
		if portElem := protocolElem.SelectElement("port"); portElem != nil {
			protocol.Port = portElem.Text()
		}
		if sslElem := protocolElem.SelectElement("socketType"); sslElem != nil {
			protocol.SSL = sslElem.Text() //<socketType> -> <SSL>
		}

		//检查

		var authentications []string
		//对authentication
		hasOAuth2 := false
		haspassword_cleartext := false
		for _, authElem := range protocolElem.SelectElements("authentication") {
			authText := authElem.Text()
			authentications = append(authentications, authText)
			if authText == "OAuth2" {
				hasOAuth2 = true
			} else if authText == "password-cleartext" {
				haspassword_cleartext = true
			}
		}
		if hasOAuth2 && len(authentications) == 1 {
			protocol.SingleCheck = "Invalid, OAuth2 must have fallback authmethod" //

		}

		if len(authentications) != 0 {
			protocol.Encryption = strings.Join(authentications, ", ")
		}

		if protocol.Type == "imap" {
			//关于端口和socketType的检查
			if protocol.SSL == "SSL" || protocol.SSL == "TLS" {
				if protocol.Port != "993" {
					protocol.SingleCheck = "Invalid, supposed IMAP-SSL-993"
				}
			} else if protocol.SSL == "STARTTLS" {
				if protocol.Port != "143" {
					protocol.SingleCheck = "Invalid, supposed IMAP-STARTTLS-143"
				}
			} else if protocol.SSL == "plain" { //plain
				if haspassword_cleartext && len(authentications) == 1 {
					protocol.SingleCheck = "Invalid, only plain method is not supposed"
				} //如果只有plain认证算Invalid
			} else { //出现了除以上三者之外别的socketType
				protocol.SingleCheck = fmt.Sprintf("Invalid, socketType %s not supposed", protocol.SSL)
			}

		} else if protocol.Type == "pop3" {
			if protocol.SSL == "SSL" || protocol.SSL == "TLS" {
				if protocol.Port != "995" {
					protocol.SingleCheck = "Invalid, supposed POP3-SSL-995"
				}
			} else if protocol.SSL == "STARTTLS" {
				if protocol.Port != "110" {
					protocol.SingleCheck = "Invalid, supposed POP3-STARTTLS-110"
				}
			} else if protocol.SSL == "plain" { //plain
				if haspassword_cleartext && len(authentications) == 1 {
					protocol.SingleCheck = "Invalid, only plain method is not supposed"
				}
			} else {
				protocol.SingleCheck = fmt.Sprintf("Invalid, socketType %s not supposed", protocol.SSL)
			}

		} else {
			protocol.SingleCheck = "Invalid, Type supposed to be imap or pop3"
		}
		protocols = append(protocols, protocol)
	}
	finalStatus1 := "Invalid"
	for _, protocol := range protocols {
		if protocol.SingleCheck == "Valid" {
			finalStatus1 = "Valid"
			break
		}
	} //设定的是incoming中有一个Valid即可,是按照priority先后顺序得到的

	var protocols2 []models.ProtocolInfo
	for _, protocolElem := range emailProviderElem.SelectElements("outgoingServer") {
		protocol := models.ProtocolInfo{}
		protocol.SingleCheck = "Valid"
		if typeELem := protocolElem.SelectAttr("type"); typeELem != nil {
			protocol.Type = typeELem.Value //? type属性 -> <Type>
		}
		if serverElem := protocolElem.SelectElement("hostname"); serverElem != nil {
			protocol.Server = serverElem.Text() //<hostname> -> <Server>
		}
		if portElem := protocolElem.SelectElement("port"); portElem != nil {
			protocol.Port = portElem.Text()
		}
		if sslElem := protocolElem.SelectElement("socketType"); sslElem != nil {
			protocol.SSL = sslElem.Text() //<socketType> -> <SSL>
		}
		// if encryptionElem := protocolElem.SelectElement("authentication"); encryptionElem != nil {
		// 	protocol.Encryption = encryptionElem.Text() //<authentication> -> <Encryption>
		// } //<username>没写

		//检查
		var authentications []string
		//对authentication
		hasOAuth2 := false
		haspassword_cleartext := false
		for _, authElem := range protocolElem.SelectElements("authentication") {
			authText := authElem.Text()
			authentications = append(authentications, authText)
			if authText == "OAuth2" {
				hasOAuth2 = true
			} else if authText == "password-cleartext" {
				haspassword_cleartext = true
			}
		}
		if hasOAuth2 && len(authentications) == 1 {
			protocol.SingleCheck = "Invalid, OAuth2 must have fallback authmethod"

		}

		if len(authentications) != 0 {
			protocol.Encryption = strings.Join(authentications, ", ")
		}

		if protocol.Type == "smtp" {
			if protocol.SSL == "SSL" || protocol.SSL == "TLS" {
				if protocol.Port != "465" { //?不确定
					protocol.SingleCheck = "Invalid, supposed SMTP-SSL-465"
				}
			} else if protocol.SSL == "STARTTLS" {
				if !(protocol.Port == "25" || protocol.Port == "2525" || protocol.Port == "587") { //?协议中没写2525
					protocol.SingleCheck = "Invalid, supposed SMTP-STARTTLS-587" //
				}
			} else if protocol.SSL == "plain" { //plain
				if haspassword_cleartext && len(authentications) == 1 {
					protocol.SingleCheck = "Invalid, only plain method is not supposed"
				}
			} else {
				protocol.SingleCheck = fmt.Sprintf("Invalid, socketType %s not supposed", protocol.SSL)
			}

		} else {
			protocol.SingleCheck = "Invalid, Type supposed to be smtp"
		}
		protocols2 = append(protocols2, protocol)
		protocols = append(protocols, protocol)
	}
	finalStatus2 := "Invalid"
	for _, protocol := range protocols2 {
		if protocol.SingleCheck == "Valid" {
			finalStatus2 = "Valid"
			break
		}
	} //设定的是outcoming中有一个Valid即可
	var finalStatus string
	if finalStatus1 == "Valid" && finalStatus2 == "Valid" {
		finalStatus = "Valid"
	} else {
		finalStatus = "Invalid"
	}
	result := &models.MethodConfig{
		Method:       "Autoconfig",
		Protocols:    protocols,
		OverallCheck: finalStatus,
	}
	return result, nil

}

// 根据 SRV 服务名称获取协议类型
func getServiceType(service string) string {
	switch {
	case strings.HasPrefix(service, "_imaps"):
		return "IMAPS"
	case strings.HasPrefix(service, "_imap"):
		return "IMAP"
	case strings.HasPrefix(service, "_pop3s"):
		return "POP3S"
	case strings.HasPrefix(service, "_pop3"):
		return "POP3"
	case strings.HasPrefix(service, "_submissions"):
		return "SMTPS"
	case strings.HasPrefix(service, "_submission"):
		return "SMTP"
	default:
		return "Unknown"
	}
}

// 解析每个对象中的Autodiscover的config
func parseConfig_SRV(SRVResult *models.SRVResult) (*models.MethodConfig, error) {
	var protocols []models.ProtocolInfo
	finalStatus := "Invalid"
	if SRVResult.RecvRecords != nil {
		for _, RecvRecord := range SRVResult.RecvRecords {
			var protocol models.ProtocolInfo
			protocol.Type = getServiceType(RecvRecord.Service)
			protocol.Server = RecvRecord.Target
			// if protocol.Server == "." {
			// 	continue //表示该服务不可使用，直接跳过 //应该在跑配置的时候已经过滤掉了
			// }
			protocol.Port = fmt.Sprintf("%d", RecvRecord.Port)
			protocol.SingleCheck = "Valid"
			if protocol.Type == "IMAPS" && protocol.Port != "993" {
				protocol.SingleCheck = "Invalid, supposed imaps-993"
			} else if protocol.Type == "IMAP" && protocol.Port != "143" { //也有用993的？
				protocol.SingleCheck = "Invalid, supposed imap-143"
			} else if protocol.Type == "POP3S" && protocol.Port != "995" {
				protocol.SingleCheck = "Invalid, supposed pop3s-995"
			} else if protocol.Type == "POP3" && protocol.Port != "110" {
				protocol.SingleCheck = "Invalid, supposed pop3-110"
			} else {
				if protocol.Type == "Unknown" {
					protocol.SingleCheck = "Invalid, unknown protocol type"
				}
			}
			if protocol.SingleCheck == "Valid" {
				finalStatus = "Valid"
			}
			protocols = append(protocols, protocol) //SRV是只要三者中有一个valid即为valid
		}
	}
	if SRVResult.SendRecords != nil {
		for _, SendRecord := range SRVResult.SendRecords {
			var protocol models.ProtocolInfo
			protocol.Type = getServiceType(SendRecord.Service)
			protocol.Server = SendRecord.Target
			protocol.Port = fmt.Sprintf("%d", SendRecord.Port)
			protocol.SingleCheck = "Valid"
			if protocol.Type == "SMTPS" && protocol.Port != "465" {
				protocol.SingleCheck = "Invalid, supposed smtps-465"
			} else if protocol.Type == "SMTP" {
				if protocol.Port == "25" { //没有考虑其他端口
					protocol.SingleCheck = "Invalid, cleartext SMTP not supposed"
				} else {
					if protocol.Port != "587" {
						protocol.SingleCheck = "Invalid, supposed smtp-587"
					}
				}
			} else {
				if protocol.Type == "Unknown" {
					protocol.SingleCheck = "Invalid, unknown protocol type"
				}
			}
			if protocol.SingleCheck == "Valid" {
				finalStatus = "Valid"
			}
			protocols = append(protocols, protocol)
		}
	}
	result := &models.MethodConfig{
		Method:       "SRV",
		Protocols:    protocols,
		OverallCheck: finalStatus,
	}
	return result, nil
}

func Check() {
	file, err := os.Open("/home/wzq/scan-website/cmd/init.jsonl") // 这里修改为 jsonl
	if err != nil {
		log.Fatalf("Failed to open file: %v", err)
	}
	defer file.Close()

	// 使用 bufio.Reader 逐行读取，避免 bufio.Scanner 的 64KB 限制
	reader := bufio.NewReader(file)
	//outputFile := "check_results320.jsonl" //3.26原
	outputFile := "/home/wzq/scan-website/cmd/check_results914_onlysome.jsonl" //3.26

	sem := make(chan struct{}, 10) // 控制并发数
	var id int64 = 0
	var wg sync.WaitGroup

	for {
		// 读取一整行
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break // 读取到文件结尾
			}
			log.Fatalf("Error reading line from file: %v", err)
		}

		// 解析 JSON
		var obj models.DomainResult
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			log.Printf("Skipping invalid JSON line: %v", err)
			continue
		}

		sem <- struct{}{} // 先占位
		wg.Add(1)
		go func(obj models.DomainResult) {
			defer wg.Done()
			defer func() { <-sem }() // 释放占位

			data := processDomainResult(obj)
			curID := atomic.AddInt64(&id, 1)
			fmt.Printf("%d\n", curID)

			if data != nil {
				if err := saveCheckResultAsJSONL(data, outputFile); err != nil {
					log.Printf("Error saving check result for %v: %v", obj.Domain, err)
				}
			}
		}(obj)
	}

	wg.Wait()
}

func saveCheckResultAsJSONL(result *models.DomainCheckResult, outputFile string) error {
	// 如果 result 为空，返回错误，避免崩溃
	if result == nil {
		return fmt.Errorf("received nil result")
	}

	// 将结果转换为 JSON 字符串
	jsonData, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("failed to marshal check result to JSON: %v", err)
	}

	// 打开文件，如果文件不存在则创建
	file, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open file for appending: %v", err)
	}
	defer file.Close()

	// 写入 JSON 数据
	writer := bufio.NewWriter(file)
	_, err = writer.Write(jsonData)
	if err != nil {
		return fmt.Errorf("failed to write to file: %v", err)
	}

	// 换行
	_, err = writer.Write([]byte("\n"))
	if err != nil {
		return fmt.Errorf("failed to write newline to file: %v", err)
	}

	// 刷新缓冲区确保写入
	writer.Flush()

	return nil
}

// func check()之后
// func Countsettings_Autodiscover() (map[string]int, int) {
// 	// 打开 .jsonl 文件
// 	file, err := os.Open("check_results2.jsonl")
// 	if err != nil {
// 		log.Fatalf("Failed to open file: %v", err)
// 	}
// 	defer file.Close()
// 	//用来统计符合条件的域名数量
// 	//count := 0
// 	reader := bufio.NewReader(file)
// 	protocolCount := map[string]int{
// 		"IMAP_143": 0,
// 		"IMAP_993": 0,
// 		//"IMAP_both":                              0,
// 		"IMAP_unexp": 0,
// 		"POP3_110":   0,
// 		"POP3_995":   0,
// 		//"POP3_both":                              0,
// 		"POP3_unexp": 0,
// 		"SMTP_465":   0,
// 		"SMTP_587":   0,
// 		"SMTP_25":    0,
// 		"SMTP_2525":  0,
// 		//"SMTP_both":                              0,
// 		"SMTP_unexp":  0,
// 		"not_any_enc": 0,
// 		"enc_ssl":     0,
// 		"enc_tls":     0,
// 		"enc_auto":    0,
// 		//"enc_starttls": 0,
// 		//"enc_defaultssl":                         0,
// 		"enc_not_valid":                          0,
// 		"ssl_not_valid":                          0,
// 		"ssl_on":                                 0,
// 		"ssl_off":                                0,
// 		"ssl_default_on":                         0,
// 		"protocol_count":                         0,
// 		"Error_root element <Autodiscover> lost": 0,
// 		"Error_missing <Response> element":       0,
// 		"Error_missing <User> element":           0,
// 		"Error_missing <DisplayName> in <User>":  0,
// 		"Error_missing <Account> element":        0,
// 		"Error_<AccountType> must be 'email'":    0,
// 		"Error_<Action> must be 'settings'":      0,
// 		"OverallCheck_not_valid":                 0,
// 	}
// 	Autodiscover_total := 0

// 	// // 创建一个扫描器逐行读取文件
// 	// scanner := bufio.NewScanner(file)
// 	// for scanner.Scan() {
// 	// 	line := scanner.Text()
// 	for {
// 		line, err := reader.ReadString('\n') // ✅ 按行读取
// 		if err != nil {
// 			break // 读完所有数据后退出
// 		}
// 		var domainCheckResult models.DomainCheckResult
// 		// 解析每一行的 JSON
// 		err = json.Unmarshal([]byte(line), &domainCheckResult)
// 		if err != nil {
// 			log.Printf("Error unmarshalling line: %v", err)
// 			continue
// 		}
// 		domain := domainCheckResult.Domain
// 		if domainCheckResult.AutodiscoverCheckResult != nil {
// 			Autodiscover_total += 1
// 		}
// 		//fmt.Print(domain + "\n")
// 		if domainCheckResult.AutodiscoverCheckResult != nil && domainCheckResult.AutodiscoverCheckResult.OverallCheck != "Valid" {
// 			//fmt.Print(domain)
// 			//Autodiscover_total += 1
// 			protocolCount["OverallCheck_not_valid"]++
// 			if domainCheckResult.AutodiscoverCheckResult.OverallCheck == "Invalid, root element <Autodiscover> lost" {
// 				protocolCount["Error_root element <Autodiscover> lost"]++
// 				save_content_tofile("./Autodiscover_Count_results.txt", domain, "Error_root element <Autodiscover> lost: ")
// 			} else if domainCheckResult.AutodiscoverCheckResult.OverallCheck == "Invalid, <Response> element lost" {
// 				protocolCount["Error_missing <Response> element"]++
// 				save_content_tofile("./Autodiscover_Count_results.txt", domain, "Error_missing <Response> element: ")
// 				// } else if domainCheckResult.AutodiscoverCheckResult.OverallCheck == "Invalid, <User> element lost" {
// 				// 	protocolCount["Error_missing <User> element"]++
// 				// 	save_content_tofile("./Autodiscover_Count_results.txt", domain, "Error_missing <User> element: ")
// 				// } else if domainCheckResult.AutodiscoverCheckResult.OverallCheck == "Invalid,missing <DisplayName> in <User>" {
// 				// 	protocolCount["Error_missing <DisplayName> in <User>"]++
// 				// 	save_content_tofile("./Autodiscover_Count_results.txt", domain, "Error_missing <DisplayName> in <User>: ")//3.8
// 			} else if domainCheckResult.AutodiscoverCheckResult.OverallCheck == "Invalid, missing <Account> element" {
// 				protocolCount["Error_missing <Account> element"]++
// 				// fmt.Print(domain)
// 				// fmt.Print("\n")
// 				save_content_tofile("./Autodiscover_Count_results.txt", domain, "Error_missing <Account> element: ")
// 			} else if domainCheckResult.AutodiscoverCheckResult.OverallCheck == "Invalid, <AccountType> must be 'email'" {
// 				protocolCount["Error_<AccountType> must be 'email'"]++
// 				save_content_tofile("./Autodiscover_Count_results.txt", domain, "Error_<AccountType> must be 'email': ")
// 			} else if domainCheckResult.AutodiscoverCheckResult.OverallCheck == "Invalid, <Action> must be 'settings'" {
// 				protocolCount["Error_<Action> must be 'settings'"]++
// 				save_content_tofile("./Autodiscover_Count_results.txt", domain, "Error_<Action> must be 'settings': ")
// 			}
// 			continue
// 		}
// 		if domainCheckResult.AutodiscoverCheckResult != nil && domainCheckResult.AutodiscoverCheckResult.OverallCheck == "Invalid, <User> element lost" {
// 			protocolCount["Error_missing <User> element"]++
// 			save_content_tofile("./Autodiscover_Count_results.txt", domain, "Error_missing <User> element: ")
// 		}
// 		if domainCheckResult.AutodiscoverCheckResult != nil && domainCheckResult.AutodiscoverCheckResult.OverallCheck == "Invalid,missing <DisplayName> in <User>" {
// 			protocolCount["Error_missing <DisplayName> in <User>"]++
// 			save_content_tofile("./Autodiscover_Count_results.txt", domain, "Error_missing <DisplayName> in <User>: ") //3.8
// 		}
// 		// 检查 AutodiscoverCheckResult 中的 Protocols
// 		if domainCheckResult.AutodiscoverCheckResult != nil && domainCheckResult.AutodiscoverCheckResult.Protocols != nil {
// 			// Autodiscover_total += 1
// 			//fmt.Print(domain)
// 			flag_imap_143 := false
// 			flag_imap_993 := false
// 			flag_imap_unexp := false
// 			flag_pop3_110 := false
// 			flag_pop3_995 := false
// 			flag_pop3_unexp := false
// 			flag_smtp_587 := false
// 			flag_smtp_465 := false
// 			flag_smtp_25 := false
// 			flag_smtp_2525 := false
// 			flag_smtp_unexp := false
// 			flag_enc_ssl := false
// 			flag_enc_tls := false
// 			flag_enc_auto := false
// 			flag_enc_none := false
// 			flag_ssl_on := false
// 			flag_ssl_off := false
// 			flag_ssl_default_on := false
// 			flag_enc_not_valid := false
// 			flag_ssl_not_valid := false
// 			for _, protocol := range domainCheckResult.AutodiscoverCheckResult.Protocols {
// 				if protocol.SingleCheck != "Valid" {
// 					save_content_tofile("./Autodiscover_Count_results.txt", domain, "protocol among Protocols is invalid': ")
// 				}
// 				// if protocol.SSL == "off" && (protocol.Encryption == "None" || protocol.Encryption == "none") {
// 				// 	protocolCount["not_any_enc"]++
// 				// } else if protocol.Encryption == "SSL" || protocol.Encryption == "ssl" || protocol.SSL == "on" {
// 				// 	protocolCount["enc_ssl"]++
// 				// } else if protocol.Encryption == "TLS" || protocol.Encryption == "tls" {
// 				// 	protocolCount["enc_tls"]++
// 				// } else if protocol.Encryption == "auto" || protocol.Encryption == "Auto" {
// 				// 	protocolCount["enc_auto"]++
// 				// } else if protocol.SSL == "starttls" || protocol.Encryption == "STARTTLS" { //这里没有考虑元素为<STARTTLS>的？
// 				// 	protocolCount["enc_starttls"]++
// 				// } else if protocol.SSL == "default(on)" {
// 				// 	protocolCount["enc_defaultssl"]++
// 				// }//3.8考虑Encryption会覆盖SSL元素
// 				if protocol.Encryption != "" {
// 					if protocol.Encryption == "SSL" {
// 						//protocolCount["enc_ssl"]++
// 						flag_enc_ssl = true
// 					} else if protocol.Encryption == "TLS" {
// 						//protocolCount["enc_tls"]++
// 						flag_enc_tls = true
// 					} else if protocol.Encryption == "Auto" {
// 						//protocolCount["enc_auto"]++
// 						flag_enc_auto = true
// 					} else if protocol.Encryption == "None" {
// 						//protocolCount["not_any_enc"]++
// 						flag_enc_none = true
// 					} else {
// 						flag_enc_not_valid = true
// 						protocolCount["enc_not_valid"]++ //不在这四个值之内的都不符合规范，需要记录
// 						save_content_tofile("./Autodiscover_Count_results.txt", protocol.Encryption, "Not valid <Encryption> value in domain "+domain+":")
// 					}
// 				} else {
// 					if protocol.SSL == "off" {
// 						//protocolCount["not_any_enc"]++
// 						flag_ssl_off = true
// 					} else if protocol.SSL == "on" {
// 						//protocolCount["enc_ssl"]++
// 						flag_ssl_on = true
// 					} else if protocol.SSL == "default(on)" {
// 						//protocolCount["enc_defaultssl"]++
// 						flag_ssl_default_on = true
// 					} else {
// 						flag_ssl_not_valid = true
// 						save_content_tofile("./Autodiscover_Count_results.txt", protocol.SSL, "Not valid <SSL> value in domain "+domain+":")
// 					}
// 				}

// 				switch protocol.Type {
// 				case "IMAP":
// 					protocolCount["protocol_count"]++
// 					if protocol.Port == "143" {
// 						flag_imap_143 = true
// 					} else if protocol.Port == "993" {
// 						flag_imap_993 = true
// 					} else {
// 						//fmt.Printf("%s,IMAP_unexp,%s\n", protocol.Server, protocol.Port)
// 						save_content_tofile("./Autodiscover_unexp_port_results.txt", protocol.Port, "unexp imap port in domain "+domain+","+protocol.Server+",")
// 						flag_imap_unexp = true
// 					}
// 				case "POP3":
// 					protocolCount["protocol_count"]++
// 					if protocol.Port == "110" {
// 						flag_pop3_110 = true
// 					} else if protocol.Port == "995" {
// 						flag_pop3_995 = true
// 					} else {
// 						save_content_tofile("./Autodiscover_unexp_port_results.txt", protocol.Port, "unexp pop3 port in domain "+domain+","+protocol.Server+",")
// 						//fmt.Printf("%s,POP3_unexp,%s\n", protocol.Server, protocol.Port)
// 						flag_pop3_unexp = true
// 					}
// 				case "SMTP":
// 					protocolCount["protocol_count"]++
// 					if protocol.Port == "465" {
// 						flag_smtp_465 = true
// 					} else if protocol.Port == "587" {
// 						flag_smtp_587 = true
// 					} else if protocol.Port == "25" {
// 						flag_smtp_25 = true
// 					} else if protocol.Port == "2525" {
// 						flag_smtp_2525 = true
// 					} else {
// 						save_content_tofile("./Autodiscover_unexp_port_results.txt", protocol.Port, "unexp smtp port in domain "+domain+","+protocol.Server+",")
// 						//fmt.Printf("%s, SMTP_unexp,%s\n", protocol.Server, protocol.Port)
// 						flag_smtp_unexp = true
// 					}
// 				}

// 			}
// 			if flag_imap_unexp {
// 				protocolCount["IMAP_unexp"]++
// 			}
// 			// if flag_imap_143 && flag_imap_993 {
// 			// 	protocolCount["IMAP_both"]++
// 			// } else if flag_imap_143 {
// 			// 	protocolCount["IMAP_only143"]++
// 			// } else if flag_imap_993 {
// 			// 	protocolCount["IMAP_only993"]++
// 			// }
// 			if flag_imap_143 {
// 				protocolCount["IMAP_143"]++
// 			}
// 			if flag_imap_993 {
// 				protocolCount["IMAP_993"]++
// 			}

// 			if flag_pop3_unexp {
// 				protocolCount["POP3_unexp"]++
// 			}
// 			// if flag_pop3_110 && flag_pop3_995 {
// 			// 	protocolCount["POP3_both"]++
// 			// } else if flag_pop3_110 {
// 			// 	protocolCount["POP3_only110"]++
// 			// } else if flag_pop3_995 {
// 			// 	protocolCount["POP3_only995"]++
// 			// }
// 			if flag_pop3_110 {
// 				protocolCount["POP3_110"]++
// 			}
// 			if flag_pop3_995 {
// 				protocolCount["POP3_995"]++
// 			}

// 			if flag_smtp_unexp {
// 				protocolCount["SMTP_unexp"]++
// 			}
// 			// if flag_smtp_465 && flag_smtp_587 {
// 			// 	protocolCount["SMTP_both"]++
// 			// } else if flag_smtp_465 {
// 			// 	protocolCount["SMTP_only465"]++
// 			// } else if flag_smtp_587 {
// 			// 	protocolCount["SMTP_only587"]++

// 			// }
// 			if flag_smtp_465 {
// 				protocolCount["SMTP_465"]++
// 			}
// 			if flag_smtp_587 {
// 				protocolCount["SMTP_587"]++
// 			}
// 			if flag_smtp_25 {
// 				protocolCount["SMTP_25"]++
// 			}
// 			if flag_smtp_2525 {
// 				protocolCount["SMTP_2525"]++
// 			}

// 			if flag_enc_auto {
// 				protocolCount["enc_auto"]++
// 			}
// 			if flag_enc_none {
// 				protocolCount["not_any_enc"]++
// 			}
// 			if flag_enc_not_valid {
// 				protocolCount["enc_not_valid"]++
// 			}
// 			if flag_enc_ssl {
// 				protocolCount["enc_ssl"]++
// 			}
// 			if flag_enc_tls {
// 				protocolCount["enc_tls"]++
// 			}

// 			if flag_ssl_default_on {
// 				protocolCount["ssl_default_on"]++
// 			}
// 			if flag_ssl_on {
// 				protocolCount["ssl_on"]++
// 			}
// 			if flag_ssl_off {
// 				protocolCount["ssl_off"]++
// 			}
// 			if flag_ssl_not_valid {
// 				protocolCount["ssl_not_valid"]++
// 			}
// 		}
// 	}

// 	// // // 输出符合条件的域名数量
// 	// // fmt.Printf("Found %d domains with imap protocol and port 993 in AutodiscoverCheckResult\n", count)

//		// // 处理文件读取错误
//		// if err := scanner.Err(); err != nil {
//		// 	log.Fatalf("Error reading file: %v", err)
//		// }
//		return protocolCount, Autodiscover_total
//	}
func Countsettings_Autodiscover_auto() (map[string]int, int) { //9.14
	file, err := os.Open("/home/wzq/scan-website/cmd/check_results914_onlysome.jsonl")
	if err != nil {
		log.Fatalf("Failed to open file: %v", err)
	}
	defer file.Close()

	reader := bufio.NewReader(file)
	protocolCount := map[string]int{
		"IMAP_143": 0, "IMAP_993": 0, "IMAP_unexp": 0,
		"POP3_110": 0, "POP3_995": 0, "POP3_unexp": 0,
		"SMTP_465": 0, "SMTP_587": 0, "SMTP_25": 0, "SMTP_2525": 0, "SMTP_unexp": 0,
		"not_any_enc": 0, "enc_ssl": 0, "enc_tls": 0, "enc_auto": 0,
		"enc_not_valid": 0, "ssl_not_valid": 0,
		"ssl_on": 0, "ssl_off": 0, "ssl_default_on": 0,
		"protocol_count":                         0,
		"Error_root element <Autodiscover> lost": 0,
		"Error_missing <Response> element":       0,
		"Error_missing <User> element":           0,
		"Error_missing <DisplayName> in <User>":  0,
		"Error_missing <Account> element":        0,
		"Error_<AccountType> must be 'email'":    0,
		"Error_<Action> must be 'settings'":      0,
		"OverallCheck_not_valid":                 0,
	}

	Autodiscover_total := 0

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}

		var domainCheckResult models.DomainCheckResult
		if err := json.Unmarshal([]byte(line), &domainCheckResult); err != nil {
			log.Printf("Error unmarshalling line: %v", err)
			continue
		}

		domain := domainCheckResult.Domain

		if domainCheckResult.AutodiscoverCheckResult != nil {
			Autodiscover_total++
		}

		for _, methodResult := range domainCheckResult.AutodiscoverCheckResult { //遍历每一个协议数组
			// ---- OverallCheck 检查 ----
			if methodResult.OverallCheck != "Valid" {
				protocolCount["OverallCheck_not_valid"]++

				switch methodResult.OverallCheck {
				case "Invalid, root element <Autodiscover> lost":
					protocolCount["Error_root element <Autodiscover> lost"]++
					save_content_tofile("./Autodiscover_Count_results.txt", domain, "Error_root element <Autodiscover> lost: ")
				case "Invalid, <Response> element lost":
					protocolCount["Error_missing <Response> element"]++
					save_content_tofile("./Autodiscover_Count_results.txt", domain, "Error_missing <Response> element: ")
				case "Invalid, <User> element lost":
					protocolCount["Error_missing <User> element"]++
					save_content_tofile("./Autodiscover_Count_results.txt", domain, "Error_missing <User> element: ")
				case "Invalid,missing <DisplayName> in <User>":
					protocolCount["Error_missing <DisplayName> in <User>"]++
					save_content_tofile("./Autodiscover_Count_results.txt", domain, "Error_missing <DisplayName> in <User>: ")
				case "Invalid, missing <Account> element":
					protocolCount["Error_missing <Account> element"]++
					save_content_tofile("./Autodiscover_Count_results.txt", domain, "Error_missing <Account> element: ")
				case "Invalid, <AccountType> must be 'email'":
					protocolCount["Error_<AccountType> must be 'email'"]++
					save_content_tofile("./Autodiscover_Count_results.txt", domain, "Error_<AccountType> must be 'email': ")
				case "Invalid, <Action> must be 'settings'":
					protocolCount["Error_<Action> must be 'settings'"]++
					save_content_tofile("./Autodiscover_Count_results.txt", domain, "Error_<Action> must be 'settings': ")
				}
			}

			// ---- Protocols 检查 ----
			if methodResult.Protocols != nil {
				flags := make(map[string]bool)

				for _, protocol := range methodResult.Protocols {
					if protocol.SingleCheck != "Valid" {
						save_content_tofile("./Autodiscover_Count_results.txt", domain, "protocol among Protocols is invalid: ")
					}

					// 检查加密方式
					if protocol.Encryption != "" {
						switch protocol.Encryption {
						case "SSL":
							flags["enc_ssl"] = true
						case "TLS":
							flags["enc_tls"] = true
						case "Auto":
							flags["enc_auto"] = true
						case "None":
							flags["not_any_enc"] = true
						default:
							flags["enc_not_valid"] = true
							protocolCount["enc_not_valid"]++
							save_content_tofile("./Autodiscover_Count_results.txt", protocol.Encryption, "Not valid <Encryption> value in domain "+domain+":")
						}
					} else {
						switch protocol.SSL {
						case "off":
							flags["ssl_off"] = true
						case "on":
							flags["ssl_on"] = true
						case "default(on)":
							flags["ssl_default_on"] = true
						default:
							flags["ssl_not_valid"] = true
							save_content_tofile("./Autodiscover_Count_results.txt", protocol.SSL, "Not valid <SSL> value in domain "+domain+":")
						}
					}

					// 检查端口
					switch protocol.Type {
					case "IMAP":
						protocolCount["protocol_count"]++
						if protocol.Port == "143" {
							flags["IMAP_143"] = true
						} else if protocol.Port == "993" {
							flags["IMAP_993"] = true
						} else {
							flags["IMAP_unexp"] = true
							save_content_tofile("./Autodiscover_unexp_port_results.txt", protocol.Port, "unexp imap port in domain "+domain+","+protocol.Server+",")
						}
					case "POP3":
						protocolCount["protocol_count"]++
						if protocol.Port == "110" {
							flags["POP3_110"] = true
						} else if protocol.Port == "995" {
							flags["POP3_995"] = true
						} else {
							flags["POP3_unexp"] = true
							save_content_tofile("./Autodiscover_unexp_port_results.txt", protocol.Port, "unexp pop3 port in domain "+domain+","+protocol.Server+",")
						}
					case "SMTP":
						protocolCount["protocol_count"]++
						if protocol.Port == "465" {
							flags["SMTP_465"] = true
						} else if protocol.Port == "587" {
							flags["SMTP_587"] = true
						} else if protocol.Port == "25" {
							flags["SMTP_25"] = true
						} else if protocol.Port == "2525" {
							flags["SMTP_2525"] = true
						} else {
							flags["SMTP_unexp"] = true
							save_content_tofile("./Autodiscover_unexp_port_results.txt", protocol.Port, "unexp smtp port in domain "+domain+","+protocol.Server+",")
						}
					}
				}

				// 最后统一加计数器
				for k := range flags {
					protocolCount[k]++
				}
			}
		}
	}

	return protocolCount, Autodiscover_total
}

func Countsettings_Autoconfig_auto() (map[string]int, int) {
	file, err := os.Open("/home/wzq/scan-website/cmd/check_results914_onlysome.jsonl")
	if err != nil {
		log.Fatalf("Failed to open file: %v", err)
	}
	defer file.Close()

	reader := bufio.NewReader(file)
	protocolCount := map[string]int{
		"IMAP_143": 0, "IMAP_993": 0, "IMAP_unexp": 0,
		"POP3_110": 0, "POP3_995": 0, "POP3_unexp": 0,
		"SMTP_465": 0, "SMTP_587": 0, "SMTP_25": 0, "SMTP_2525": 0, "SMTP_unexp": 0,
		"SSL": 0, "TLS": 0, "STARTTLS": 0, "plain": 0,
		"ssl_not_valid": 0, "protocol_count": 0,
		"Error_missing root element <clientConfig>": 0,
		"Error_missing <emailProvider> element":     0,
		"finalStatus_not_valid":                     0,
	}

	Autoconfig_total := 0

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}

		var domainCheckResult models.DomainCheckResult
		if err := json.Unmarshal([]byte(line), &domainCheckResult); err != nil {
			log.Printf("Error unmarshalling line: %v", err)
			continue
		}

		domain := domainCheckResult.Domain
		if domainCheckResult.AutoconfigCheckResult != nil {
			Autoconfig_total++
		}

		for _, methodResult := range domainCheckResult.AutoconfigCheckResult {
			// ---- OverallCheck 检查 ----
			if methodResult.OverallCheck != "Valid" {
				protocolCount["finalStatus_not_valid"]++

				switch methodResult.OverallCheck {
				case "Invalid, root element <clientConfig> lost":
					protocolCount["Error_missing root element <clientConfig>"]++
					save_content_tofile("./Autoconfig_Count_results.txt", domain, "Error_missing root element <clientConfig>: ")
				case "Invalid, <emailProvider> element lost":
					protocolCount["Error_missing <emailProvider> element"]++
					save_content_tofile("./Autoconfig_Count_results.txt", domain, "Error_missing <emailProvider> element: ")
				}
				continue
			}

			// ---- Protocols 检查 ----
			if methodResult.Protocols != nil {
				flags := make(map[string]bool)

				for _, protocol := range methodResult.Protocols {
					if protocol.SingleCheck != "Valid" {
						save_content_tofile("./Autoconfig_Count_results.txt", domain, "protocol among Protocols is invalid: ")
					}

					// ---- SSL / TLS / STARTTLS / plain ----
					switch strings.ToLower(protocol.SSL) {
					case "ssl":
						flags["SSL"] = true
					case "tls":
						flags["TLS"] = true
					case "starttls":
						flags["STARTTLS"] = true
					case "plain":
						flags["plain"] = true
					default:
						flags["ssl_not_valid"] = true
						save_content_tofile("./Autoconfig_Count_results.txt", protocol.SSL, "Not valid <SSL> value in domain "+domain+":")
					}

					// ---- 端口检查 ----
					switch strings.ToLower(protocol.Type) {
					case "imap":
						protocolCount["protocol_count"]++
						if protocol.Port == "143" {
							flags["IMAP_143"] = true
						} else if protocol.Port == "993" {
							flags["IMAP_993"] = true
						} else {
							flags["IMAP_unexp"] = true
							save_content_tofile("./Autoconfig_unexp_port_results.txt", protocol.Port, "unexp imap port in domain "+domain+","+protocol.Server+",")
						}
					case "pop3":
						protocolCount["protocol_count"]++
						if protocol.Port == "110" {
							flags["POP3_110"] = true
						} else if protocol.Port == "995" {
							flags["POP3_995"] = true
						} else {
							flags["POP3_unexp"] = true
							save_content_tofile("./Autoconfig_unexp_port_results.txt", protocol.Port, "unexp pop3 port in domain "+domain+","+protocol.Server+",")
						}
					case "smtp":
						protocolCount["protocol_count"]++
						if protocol.Port == "465" {
							flags["SMTP_465"] = true
						} else if protocol.Port == "587" {
							flags["SMTP_587"] = true
						} else if protocol.Port == "25" {
							flags["SMTP_25"] = true
						} else if protocol.Port == "2525" {
							flags["SMTP_2525"] = true
						} else {
							flags["SMTP_unexp"] = true
							save_content_tofile("./Autoconfig_unexp_port_results.txt", protocol.Port, "unexp smtp port in domain "+domain+","+protocol.Server+",")
						}
					}
				}

				// ---- 统一累计 ----
				for k := range flags {
					protocolCount[k]++
				}
			}
		}
	}

	return protocolCount, Autoconfig_total
}

func Countsettings_SRV() (map[string]int, int) {
	file, err := os.Open("/home/wzq/scan-website/cmd/check_results914_onlysome.jsonl")
	if err != nil {
		log.Fatalf("Failed to open file: %v", err)
	}
	defer file.Close()
	reader := bufio.NewReader(file)
	protocolCount := map[string]int{
		"IMAP_143":    0,
		"IMAP_993":    0,
		"IMAP_unexp":  0,
		"IMAPS_143":   0,
		"IMAPS_993":   0,
		"IMAPS_unexp": 0,
		"POP3_110":    0,
		"POP3_995":    0,
		"POP3_unexp":  0,
		"POP3S_110":   0,
		"POP3S_995":   0,
		"POP3S_unexp": 0,
		"SMTP_465":    0,
		"SMTP_587":    0,
		"SMTP_25":     0,
		"SMTP_2525":   0,
		"SMTP_unexp":  0,
		"SMTPS_465":   0,
		"SMTPS_587":   0,
		"SMTPS_25":    0,
		"SMTPS_2525":  0,
		"SMTPS_unexp": 0,
		// "SSL":            0,
		// "TLS":            0,
		// "STARTTLS":       0,
		// "plain":          0,
		// "ssl_not_valid":  0,
		"protocol_count": 0,
		// "Error_missing root element <clientConfig>": 0,
		// "Error_missing <emailProvider> element":     0,
		"OverallCheck_not_valid": 0,
	}
	SRV_total := 0

	for {
		line, err := reader.ReadString('\n') // ✅ 按行读取
		if err != nil {
			break // 读完所有数据后退出
		}
		var domainCheckResult models.DomainCheckResult
		// 解析每一行的 JSON
		err = json.Unmarshal([]byte(line), &domainCheckResult)
		if err != nil {
			log.Printf("Error unmarshalling line: %v", err)
			continue
		}
		domain := domainCheckResult.Domain
		if domainCheckResult.SRVCheckResult != nil {
			SRV_total += 1
		}
		if domainCheckResult.SRVCheckResult != nil && domainCheckResult.SRVCheckResult.OverallCheck != "Valid" {
			protocolCount["OverallCheck_not_valid"]++
			//continue
		}
		if domainCheckResult.SRVCheckResult != nil && domainCheckResult.SRVCheckResult.Protocols != nil {
			flag_imap_143 := false
			flag_imap_993 := false
			flag_imap_unexp := false
			flag_imaps_143 := false
			flag_imaps_993 := false
			flag_imaps_unexp := false
			flag_pop3_110 := false
			flag_pop3_995 := false
			flag_pop3_unexp := false
			flag_pop3s_110 := false
			flag_pop3s_995 := false
			flag_pop3s_unexp := false
			flag_smtp_587 := false
			flag_smtp_465 := false
			flag_smtp_unexp := false
			flag_smtp_25 := false
			flag_smtp_2525 := false
			flag_smtps_587 := false
			flag_smtps_465 := false
			flag_smtps_unexp := false
			flag_smtps_25 := false
			flag_smtps_2525 := false
			for _, protocol := range domainCheckResult.SRVCheckResult.Protocols {
				if protocol.SingleCheck != "Valid" {
					save_content_tofile("./SRV_Count_results.txt", domain, "protocol among Protocols is invalid': ")
				}
				switch protocol.Type {
				case "IMAP":
					protocolCount["protocol_count"]++
					if protocol.Port == "143" {
						flag_imap_143 = true
					} else if protocol.Port == "993" {
						flag_imap_993 = true
					} else {
						save_content_tofile("./SRV_unexp_port_results.txt", protocol.Port, "unexp imap port in domain "+domain+","+protocol.Server+",")
						flag_imap_unexp = true
					}
				case "IMAPS":
					protocolCount["protocol_count"]++
					if protocol.Port == "143" {
						flag_imaps_143 = true
					} else if protocol.Port == "993" {
						flag_imaps_993 = true
					} else {
						save_content_tofile("./SRV_unexp_port_results.txt", protocol.Port, "unexp imaps port in domain "+domain+","+protocol.Server+",")
						flag_imaps_unexp = true
					}
				case "POP3":
					protocolCount["protocol_count"]++
					if protocol.Port == "110" {
						flag_pop3_110 = true
					} else if protocol.Port == "995" {
						flag_pop3_995 = true
					} else {
						save_content_tofile("./SRV_unexp_port_results.txt", protocol.Port, "unexp pop3 port in domain "+domain+","+protocol.Server+",")
						flag_pop3_unexp = true
					}
				case "POP3S":
					protocolCount["protocol_count"]++
					if protocol.Port == "110" {
						flag_pop3s_110 = true
					} else if protocol.Port == "995" {
						flag_pop3s_995 = true
					} else {
						save_content_tofile("./SRV_unexp_port_results.txt", protocol.Port, "unexp pop3s port in domain "+domain+","+protocol.Server+",")
						flag_pop3s_unexp = true
					}
				case "SMTP":
					protocolCount["protocol_count"]++
					if protocol.Port == "465" {
						flag_smtp_465 = true
					} else if protocol.Port == "587" {
						flag_smtp_587 = true
					} else if protocol.Port == "25" {
						flag_smtp_25 = true
					} else if protocol.Port == "2525" {
						flag_smtp_2525 = true
					} else {
						save_content_tofile("./SRV_unexp_port_results.txt", protocol.Port, "unexp smtp port in domain "+domain+","+protocol.Server+",")
						flag_smtp_unexp = true
					}
				case "SMTPS":
					protocolCount["protocol_count"]++
					if protocol.Port == "465" {
						flag_smtps_465 = true
					} else if protocol.Port == "587" {
						flag_smtps_587 = true
					} else if protocol.Port == "25" {
						flag_smtps_25 = true
					} else if protocol.Port == "2525" {
						flag_smtps_2525 = true
					} else {
						save_content_tofile("./SRV_unexp_port_results.txt", protocol.Port, "unexp smtps port in domain "+domain+","+protocol.Server+",")
						flag_smtps_unexp = true
					}
				}
			}

			if flag_imap_unexp {
				protocolCount["IMAP_unexp"]++
			}
			if flag_imap_143 {
				protocolCount["IMAP_143"]++
			}
			if flag_imap_993 {
				protocolCount["IMAP_993"]++
			}
			if flag_imaps_unexp {
				protocolCount["IMAPS_unexp"]++
			}
			if flag_imaps_143 {
				protocolCount["IMAPS_143"]++
			}
			if flag_imaps_993 {
				protocolCount["IMAPS_993"]++
			}

			if flag_pop3_unexp {
				protocolCount["POP3_unexp"]++
			}
			if flag_pop3_110 {
				protocolCount["POP3_110"]++
			}
			if flag_pop3_995 {
				protocolCount["POP3_995"]++
			}
			if flag_pop3s_unexp {
				protocolCount["POP3S_unexp"]++
			}
			if flag_pop3s_110 {
				protocolCount["POP3S_110"]++
			}
			if flag_pop3s_995 {
				protocolCount["POP3S_995"]++
			}

			if flag_smtp_unexp {
				protocolCount["SMTP_unexp"]++
			}
			if flag_smtp_465 {
				protocolCount["SMTP_465"]++
			}
			if flag_smtp_587 {
				protocolCount["SMTP_587"]++
			}
			if flag_smtp_25 {
				protocolCount["SMTP_25"]++
			}
			if flag_smtp_2525 {
				protocolCount["SMTP_2525"]++
			}
			if flag_smtps_unexp {
				protocolCount["SMTPS_unexp"]++
			}
			if flag_smtps_465 {
				protocolCount["SMTPS_465"]++
			}
			if flag_smtps_587 {
				protocolCount["SMTPS_587"]++
			}
			if flag_smtps_25 {
				protocolCount["SMTPS_25"]++
			}
			if flag_smtps_2525 {
				protocolCount["SMTPS_2525"]++
			}

		}

	}

	return protocolCount, SRV_total

}

func save_content_tofile(fileName string, content string, inputFile string) { //记录数据统计结果到文件的函数
	// 打开文件，使用追加模式，如果不存在则创建
	file, err := os.OpenFile(fileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Error opening file: %v\n", err)
		return
	}
	defer file.Close()

	inputfile_Name := filepath.Base(inputFile)
	// 写入内容
	content1 := inputfile_Name + content
	_, err = file.WriteString(content1 + "\n") // 每次追加一行内容
	if err != nil {
		fmt.Printf("Error writing to file: %v\n", err)
		return
	}
	//fmt.Printf("Successfully wrote to file: %s\n", fileName)
}

func write_map_ToFile(fileName string, data map[string]int, method string) error {
	// 检查文件是否存在，若不存在则创建
	_, err := os.Stat(fileName)
	if os.IsNotExist(err) {
		// 文件不存在，创建文件
		_, err := os.Create(fileName)
		if err != nil {
			return fmt.Errorf("fail to create file: %v", err)
		}
	}

	// 以追加模式打开文件
	file, err := os.OpenFile(fileName, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("fail to open file: %v", err)
	}
	defer file.Close()

	file.WriteString("\n" + "Count result for Method: " + method + "\n")
	// 遍历 map 并写入文件
	for key, value := range data {
		line := fmt.Sprintf("%s:%d\n", key, value)
		_, err := file.WriteString(line)
		if err != nil {
			return fmt.Errorf("fail to write to file: %v", err)
		}
	}

	return nil
}
func save_number_tofile(fileName string, number int, inputFile string) { //记录数据统计结果到文件的函数
	// 打开文件，使用追加模式，如果不存在则创建
	file, err := os.OpenFile(fileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Error opening file: %v\n", err)
		return
	}
	defer file.Close()

	inputfile_Name := filepath.Base(inputFile)
	// 写入内容
	content := fmt.Sprintf(inputfile_Name+": "+"%d", number)
	_, err = file.WriteString(content + "\n") // 每次追加一行内容
	if err != nil {
		fmt.Printf("Error writing to file: %v\n", err)
		return
	}
	fmt.Printf("Successfully wrote to file: %s\n", fileName)
}

func Count() {
	// protocolCount1, Autodiscover_total := Countsettings_Autodiscover_auto()
	// // fmt.Println(protocolCount1)
	// write_map_ToFile("./Count_results.txt", protocolCount1, "Autodiscover")
	// fmt.Printf("Usage of Autodiscover:%d\n", Autodiscover_total)
	// save_number_tofile("./Count_results.txt", Autodiscover_total, "Usage of Autodiscover")

	// protocolCount2, Autoconfig_total := Countsettings_Autoconfig_auto()
	// write_map_ToFile("./Count_results.txt", protocolCount2, "Autoconfig")
	// fmt.Printf("Usage of Autoconfig:%d\n", Autoconfig_total)
	// save_number_tofile("./Count_results.txt", Autoconfig_total, "Usage of Autoconfig")

	protocolCount3, SRV_total := Countsettings_SRV()
	write_map_ToFile("./Count_results.txt", protocolCount3, "SRV")
	fmt.Printf("Usage of SRV:%d\n", SRV_total)
	save_number_tofile("./Count_results.txt", SRV_total, "Usage of SRV")

}

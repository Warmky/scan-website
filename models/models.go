package models

import (
	"encoding/xml"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

type AuthInfo struct {
	EightBitMIME        string `json:"8bitmime"`
	Pipelining          string `json:"pipelining"`
	Size                string `json:"size"`
	StartTLS            string `json:"starttls"`
	Auth                string `json:"auth"`
	DSN                 string `json:"dsn"`
	EnhancedStatusCodes string `json:"enhancedstatuscodes"`
}
type TLSInfo struct {
	Error   []string      `json:"error"`
	Version string        `json:"version"`
	Cipher  []interface{} `json:"cipher"`
	TLSCA   string        `json:"tls ca"`
	//Auth    AuthInfo      `json:"auth"`
}

type ConnectInfo struct {
	Success bool     `json:"success"`
	Info    *TLSInfo `json:"info"` // 注意：需要是指针，才能兼容 null
	Error   string   `json:"error,omitempty"`
}

type ProtocolInfo struct {
	Type           string `json:"Type"`
	Server         string `json:"Server"`
	Port           string `json:"Port"`
	DomainRequired string `json:"DomainRequired,omitempty"`
	SPA            string `json:"SPA,omitempty"`
	SSL            string `json:"SSL,omitempty"` //
	AuthRequired   string `json:"AuthRequired,omitempty"`
	Encryption     string `json:"Encryption,omitempty"`
	UsePOPAuth     string `json:"UsePOPAuth,omitempty"`
	SMTPLast       string `json:"SMTPLast,omitempty"`
	TTL            string `json:"TTL,omitempty"`
	SingleCheck    string `json:"SingleCheck"`        //          // Status 用于标记某个Method(Autodiscover/Autoconfig/SRV)的单个Protocol检查结果
	Priority       string `json:"Priority,omitempty"` //SRV
	Weight         string `json:"Weight,omitempty"`
}
type DomainResult struct {
	Domain_id     int                  `json:"id"`
	Domain        string               `json:"domain"`
	CNAME         []string             `json:"cname,omitempty"`
	Autodiscover  []AutodiscoverResult `json:"autodiscover"`
	Autoconfig    []AutoconfigResult   `json:"autoconfig"`
	SRV           SRVResult            `json:"srv"`
	GUESS         []string             `json:"guess"` //9.13
	Timestamp     string               `json:"timestamp"`
	ErrorMessages []string             `json:"errors"`
}

type AutoconfigResponse struct {
	XMLName xml.Name `xml:"clientConfig"`
}

type AutodiscoverResponse struct {
	XMLName  xml.Name `xml:"http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006 Autodiscover"`
	Response Response `xml:"http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a Response"` //3.13原 是规范的写法，但是有的配置中没有命名空间，导致解析不到Response直接算作成功获取配置信息了
}

type Response struct {
	User    User    `xml:"User"`
	Account Account `xml:"Account"`
	Error   *Error  `xml:"Error,omitempty"`
}

type User struct {
	AutoDiscoverSMTPAddress string `xml:"AutoDiscoverSMTPAddress"`
	DisplayName             string `xml:"DisplayName"`
	LegacyDN                string `xml:"LegacyDN"`
	DeploymentId            string `xml:"DeploymentId"`
}

type Account struct {
	AccountType     string   `xml:"AccountType"`
	Action          string   `xml:"Action"`
	MicrosoftOnline string   `xml:"MicrosoftOnline"`
	ConsumerMailbox string   `xml:"ConsumerMailbox"`
	Protocol        Protocol `xml:"Protocol"`
	RedirectAddr    string   `xml:"RedirectAddr"`
	RedirectUrl     string   `xml:"RedirectUrl"`
}

type Protocol struct{}

type Error struct {
	Time      string `xml:"Time,attr"`
	Id        string `xml:"Id,attr"`
	DebugData string `xml:"DebugData"`
	ErrorCode int    `xml:"ErrorCode"`
	Message   string `xml:"Message"`
}

type CertInfo struct {
	IsTrusted       bool
	VerifyError     string
	IsHostnameMatch bool
	IsInOrder       string
	IsExpired       bool
	IsSelfSigned    bool
	SignatureAlg    string
	AlgWarning      string
	TLSVersion      uint16
	Subject         string
	Issuer          string
	RawCert         []byte
	RawCerts        []string //8.15
}

// AutodiscoverResult 保存每次Autodiscover查询的结果
type AutodiscoverResult struct {
	Domain            string                   `json:"domain"`
	AutodiscoverCNAME []string                 `json:"autodiscovercname,omitempty"`
	Method            string                   `json:"method"` // 查询方法，如 POST, GET, SRV
	Index             int                      `json:"index"`
	URI               string                   `json:"uri"`       // 查询的 URI
	Redirects         []map[string]interface{} `json:"redirects"` // 重定向链
	Config            string                   `json:"config"`    // 配置信息
	CertInfo          *CertInfo                `json:"cert_info"`
	Error             string                   `json:"error"` // 错误信息（如果有）
}

// AutoconfigResult 保存每次Autoconfig查询的结果
type AutoconfigResult struct {
	Domain    string                   `json:"domain"`
	Method    string                   `json:"method"`
	Index     int                      `json:"index"`
	URI       string                   `json:"uri"`
	Redirects []map[string]interface{} `json:"redirects"`
	Config    string                   `json:"config"`
	CertInfo  *CertInfo                `json:"cert_info"`
	Error     string                   `json:"error"`
}

type SRVRecord struct {
	Service  string
	Priority uint16
	Weight   uint16
	Port     uint16
	Target   string
}

type DNSRecord struct {
	Domain      string `json:"domain"`
	SOA         string `json:"SOA,omitempty"`
	NS          string `json:"NS,omitempty"`
	ADbit_imap  *bool  `json:"ADbit_imap,omitempty"`
	ADbit_imaps *bool  `json:"ADbit_imaps,omitempty"`
	ADbit_pop3  *bool  `json:"ADbit_pop3,omitempty"`
	ADbit_pop3s *bool  `json:"ADbit_pop3s,omitempty"`
	ADbit_smtp  *bool  `json:"ADbit_smtp,omitempty"`
	ADbit_smtps *bool  `json:"ADbit_smtps,omitempty"`
}

type SRVResult struct {
	Domain      string      `json:"domain"`
	RecvRecords []SRVRecord `json:"recv_records,omitempty"` // 收件服务 (IMAP/POP3)
	SendRecords []SRVRecord `json:"send_records,omitempty"` // 发件服务 (SMTP)
	DNSRecord   *DNSRecord  `json:"dns_record,omitempty"`
}

// 8.10
type GuessResult struct {
	Host     string   `json:"host"`
	Port     int      `json:"port"`
	Protocol string   `json:"protocol"`
	IPs      []string `json:"ips"`
	Reach    bool     `json:"reach"`
}

// 尝试在界面展示Recently Seen 5.19
type ScanHistory struct {
	Domain    string    `json:"domain"`
	Timestamp time.Time `json:"timestamp"`
	Score     int       `json:"score"` // 新增：总分
	Grade     string    `json:"grade"` // 新增：等级，如 A/B/C/F
}

// 尝试保留原配置中的数据结构以供推荐时使用
type PortUsageDetail struct {
	Protocol string `json:"protocol"` // SMTP / IMAP / POP3
	Port     string `json:"port"`
	Status   string `json:"status"` // "secure" / "insecure" / "nonstandard"
	Host     string `json:"host"`   //7.27
	SSL      string `json:"ssl"`    //7.27
}

type ConnectDetail struct {
	Type     string      `json:"type"` // imap / smtp / pop3
	Host     string      `json:"host"`
	Port     string      `json:"port"`
	Plain    ConnectInfo `json:"plain"`
	StartTLS ConnectInfo `json:"starttls"`
	TLS      ConnectInfo `json:"tls"`
}

type ProgressUpdate struct {
	Type     string `json:"type"`     // 固定 "progress"
	Progress int    `json:"progress"` // 0 ~ 100
	Stage    string `json:"stage"`    // autodiscover / autoconfig / srv / guess
	Message  string `json:"message"`  // 说明文字
}

type MethodConfig struct {
	Method       string         `json:"Method"`
	Protocols    []ProtocolInfo `json:"Protocols"`
	OverallCheck string         `json:"OverallCheck"`
}

//	type ProtocolInfo struct {
//		Type           string `json:"Type"`
//		Server         string `json:"Server"`
//		Port           string `json:"Port"`
//		DomainRequired string `json:"DomainRequired,omitempty"`
//		SPA            string `json:"SPA,omitempty"`
//		SSL            string `json:"SSL,omitempty"` //
//		AuthRequired   string `json:"AuthRequired,omitempty"`
//		Encryption     string `json:"Encryption,omitempty"`
//		UsePOPAuth     string `json:"UsePOPAuth,omitempty"`
//		SMTPLast       string `json:"SMTPLast,omitempty"`
//		TTL            string `json:"TTL,omitempty"`
//		SingleCheck    string `json:"SingleCheck"`        //          // Status 用于标记某个Method(Autodiscover/Autoconfig/SRV)的单个Protocol检查结果
//		Priority       string `json:"Priority,omitempty"` //SRV
//		Weight         string `json:"Weight,omitempty"`
//	}
type DomainCheckResult struct {
	Domain                   string          `json:"Domain"`
	AutodiscoverCheckResult  []*MethodConfig `json:"AutodiscoverCheckResult,omitempty"` //以防有不同path的config不一致的情况，用数组表示
	AutoconfigCheckResult    []*MethodConfig `json:"AutoconfigCheckResult,omitempty"`
	SRVCheckResult           *MethodConfig   `json:"SRVCheckResult,omitempty"`
	AutodiscoverInconsistent bool            `json:"AutodiscoverInconsistent,omitempty"` // 只针对 Autodiscover
	AutoconfigInconsistent   bool            `json:"AutoconfigInconsistent,omitempty"`   // 只针对 Autoconfig
	Inconsistent             bool            `json:"Inconsistent,omitempty"`             // 记录是否有不一致的情况
} //9.14

var (
	//msg       = new(dns.Msg)
	DnsServer = "8.8.8.8:53"
	//client    = new(dns.Client)
)

var RecentScans []ScanHistory

const MaxRecent = 20

var Semaphore = make(chan struct{}, 10) // 控制并发数8.18

// 8.15TODO
var TempDataStore = make(map[string]interface{})

// 8.20
var Upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

// 8.23
var ProgressClients = make(map[*websocket.Conn]bool)
var ProgressBroadcast = make(chan ProgressUpdate)

var FileLocks sync.Map //存储每个文件的锁

package utils

import (
	"fmt"
	"scan-website/models"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"
)

// DNS查询相关函数
func LookupSRVWithAD_autodiscover(domain string) (string, bool, error) {
	// DNS Resolver configuration
	resolverAddr := "8.8.8.8:53" // Google Public DNS
	timeout := 5 * time.Second   // Timeout for DNS query

	// Create a DNS client
	client := &dns.Client{
		Net:     "udp", //
		Timeout: timeout,
	}

	// Create the SRV query
	service := "_autodiscover._tcp." + domain
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(service), dns.TypeSRV)
	msg.RecursionDesired = true // Enable recursion
	msg.SetEdns0(4096, true)    // true 表示启用 DO 位，支持 DNSSEC

	// Perform the DNS query
	response, _, err := client.Exchange(msg, resolverAddr)
	if err != nil {
		return "", false, fmt.Errorf("DNS query failed: %v", err)
	}

	// Check the AD bit in the DNS response flags
	adBit := response.AuthenticatedData

	var srvRecords []*dns.SRV
	for _, ans := range response.Answer {
		if srv, ok := ans.(*dns.SRV); ok {
			srvRecords = append(srvRecords, srv)
		}
	}
	var uriDNS string
	if len(srvRecords) > 0 {
		sort.Slice(srvRecords, func(i, j int) bool {
			if srvRecords[i].Priority == srvRecords[j].Priority {
				return srvRecords[i].Weight > srvRecords[j].Weight
			}
			return srvRecords[i].Priority < srvRecords[j].Priority
		})

		hostname := srvRecords[0].Target
		port := srvRecords[0].Port
		if hostname != "." {
			if port == 443 {
				uriDNS = fmt.Sprintf("https://%s/autodiscover/autodiscover.xml", hostname)
			} else if port == 80 {
				uriDNS = fmt.Sprintf("http://%s/autodiscover/autodiscover.xml", hostname)
			} else {
				uriDNS = fmt.Sprintf("https://%s:%d/autodiscover/autodiscover.xml", hostname, port)
			}
		} else {
			return "", adBit, fmt.Errorf("hostname == '.'")
		}
	} else {
		return "", adBit, fmt.Errorf("no srvRecord found")
	}

	return uriDNS, adBit, nil
}

// 查询CNAME部分
func LookupCNAME(domain string) ([]string, error) {
	resolverAddr := "8.8.8.8:53" // Google Public DNS
	timeout := 5 * time.Second   // Timeout for DNS query

	client := &dns.Client{
		Net:     "udp",
		Timeout: timeout,
	}

	var lastErr error
	for i := 0; i < 3; i++ {
		m := dns.Msg{}
		m.SetQuestion(dns.Fqdn(domain), dns.TypeA) // 查询 A 记录
		r, _, err := client.Exchange(&m, resolverAddr)
		if err != nil {
			lastErr = err
			time.Sleep(1 * time.Second * time.Duration(i+1))
			continue
		}

		var dst []string
		for _, ans := range r.Answer {
			if record, ok := ans.(*dns.CNAME); ok {
				dst = append(dst, record.Target)
			}
		}

		if len(dst) > 0 {
			return dst, nil // 如果找到结果，立即返回
		}

		lastErr = nil
		break
	}

	return nil, lastErr
}

// 获取MX记录
func ResolveMXRecord(domain string) (string, error) {
	//创建DNS客户端并设置超时时间
	client := &dns.Client{
		Timeout: 15 * time.Second, // 设置超时时间
	}

	// 创建DNS消息
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeMX)
	//发送DNS查询
	response, _, err := client.Exchange(msg, models.DnsServer)
	if err != nil {
		fmt.Printf("Failed to query DNS for %s: %v\n", domain, err)
		return "", err
	}

	//处理响应
	if response.Rcode != dns.RcodeSuccess {
		fmt.Printf("DNS query failed with Rcode %d\n", response.Rcode)
		return "", fmt.Errorf("DNS query failed with Rcode %d", response.Rcode)
	}

	var mxRecords []*dns.MX
	for _, ans := range response.Answer {
		if mxRecord, ok := ans.(*dns.MX); ok {
			fmt.Printf("MX record for %s: %s, the priority is %d\n", domain, mxRecord.Mx, mxRecord.Preference)
			mxRecords = append(mxRecords, mxRecord)
		}
	}
	if len(mxRecords) == 0 {
		return "", fmt.Errorf("no MX Record")
	}

	// 根据Preference字段排序，Preference值越小优先级越高
	sort.Slice(mxRecords, func(i, j int) bool {
		return mxRecords[i].Preference < mxRecords[j].Preference
	})
	highestMX := mxRecords[0]
	return highestMX.Mx, nil

}

// 提取%MXFULLDOMAIN%和%MXMAINDOMAIN%
func ExtractDomains(mxHost string) (string, string, error) {
	mxHost = strings.TrimSuffix(mxHost, ".")

	// 获取%MXFULLDOMAIN%
	parts := strings.Split(mxHost, ".")
	if len(parts) < 2 {
		return "", "", fmt.Errorf("invalid MX Host name: %s", mxHost)
	}
	mxFullDomain := strings.Join(parts[1:], ".")
	fmt.Println("fulldomain:", mxFullDomain)

	// 获取%MXMAINDOMAIN%（提取第二级域名）
	mxMainDomain, err := publicsuffix.EffectiveTLDPlusOne(mxHost)
	if err != nil {
		return "", "", fmt.Errorf("cannot extract maindomain: %v", err)
	}
	fmt.Println("maindomain:", mxMainDomain)

	return mxFullDomain, mxMainDomain, nil
}

package discover

import (
	"fmt"
	"scan-website/models"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

func QuerySRV(domain string) models.SRVResult {
	var dnsrecord models.DNSRecord
	dnsManager, isSOA, err := queryDNSManager(domain)
	if err != nil {
		fmt.Printf("Failed to query DNS manager for %s: %v\n", domain, err)
	} else {
		if isSOA {
			dnsrecord = models.DNSRecord{
				Domain: domain,
				SOA:    dnsManager,
			}
		} else {
			dnsrecord = models.DNSRecord{
				Domain: domain,
				NS:     dnsManager,
			}
		}
	}

	// 定义要查询的服务标签
	recvServices := []string{
		"_imap._tcp." + domain,
		"_imaps._tcp." + domain,
		"_pop3._tcp." + domain,
		"_pop3s._tcp." + domain,
	}
	sendServices := []string{
		"_submission._tcp." + domain,
		"_submissions._tcp." + domain,
	}

	var recvRecords, sendRecords []models.SRVRecord

	// 查询(IMAP/POP3)
	for _, service := range recvServices {
		records, adBit, err := lookupSRVWithAD_srv(service)
		//record_ADbit_SRV(service, "SRV_record_ad_srv.txt", domain, adBit)

		if err != nil || len(records) == 0 {
			fmt.Printf("Failed to query SRV for %s or no records found: %v\n", service, err)
			continue
		}

		// 更新 DNSRecord 的 AD 位
		if strings.HasPrefix(service, "_imaps") {
			dnsrecord.ADbit_imaps = &adBit
		} else if strings.HasPrefix(service, "_imap") {
			dnsrecord.ADbit_imap = &adBit
		} else if strings.HasPrefix(service, "_pop3s") {
			dnsrecord.ADbit_pop3s = &adBit
		} else if strings.HasPrefix(service, "_pop3") {
			dnsrecord.ADbit_pop3 = &adBit
		}

		// 添加 SRV 记录
		for _, record := range records {
			if record.Target == "." {
				continue
			}
			recvRecords = append(recvRecords, models.SRVRecord{
				Service:  service,
				Priority: record.Priority,
				Weight:   record.Weight,
				Port:     record.Port,
				Target:   record.Target,
			})
		}
	}

	// 查询 (SMTP)
	for _, service := range sendServices {
		records, adBit, err := lookupSRVWithAD_srv(service)
		//record_ADbit_SRV(service, "SRV_record_ad_srv.txt", domain, adBit)

		if err != nil || len(records) == 0 {
			fmt.Printf("Failed to query SRV for %s or no records found: %v\n", service, err)
			continue
		}

		// 更新 DNSRecord 的 AD 位
		if strings.HasPrefix(service, "_submissions") {
			dnsrecord.ADbit_smtps = &adBit
		} else if strings.HasPrefix(service, "_submission") {
			dnsrecord.ADbit_smtp = &adBit
		}

		// 添加 SRV 记录
		for _, record := range records {
			if record.Target == "." {
				continue
			}
			sendRecords = append(sendRecords, models.SRVRecord{
				Service:  service,
				Priority: record.Priority,
				Weight:   record.Weight,
				Port:     record.Port,
				Target:   record.Target,
			})
		}
	}

	// 对收件服务和发件服务进行排序
	sort.Slice(recvRecords, func(i, j int) bool {
		if recvRecords[i].Priority == recvRecords[j].Priority {
			return recvRecords[i].Weight > recvRecords[j].Weight
		}
		return recvRecords[i].Priority < recvRecords[j].Priority
	})

	sort.Slice(sendRecords, func(i, j int) bool {
		if sendRecords[i].Priority == sendRecords[j].Priority {
			return sendRecords[i].Weight > sendRecords[j].Weight
		}
		return sendRecords[i].Priority < sendRecords[j].Priority
	})

	// 返回组合后的结果
	return models.SRVResult{
		Domain:      domain,
		DNSRecord:   &dnsrecord,
		RecvRecords: recvRecords,
		SendRecords: sendRecords,
	}
}

func queryDNSManager(domain string) (string, bool, error) {
	resolverAddr := "8.8.8.8:53" // Google Public DNS
	timeout := 15 * time.Second  // DNS 查询超时时间

	client := &dns.Client{
		Net:     "udp",
		Timeout: timeout,
	}

	// 查询 SOA 记录
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeSOA)
	response, _, err := client.Exchange(msg, resolverAddr)
	if err != nil {
		return "", false, fmt.Errorf("SOA query failed: %v", err)
	}

	// 提取 SOA 记录的管理者信息
	for _, ans := range response.Answer {
		if soa, ok := ans.(*dns.SOA); ok {
			return soa.Ns, true, nil // SOA 记录中的权威 DNS 服务器名称
		}
	}

	// 若 SOA 查询无结果，尝试查询 NS 记录
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeNS)
	response, _, err = client.Exchange(msg, resolverAddr)
	if err != nil {
		return "", false, fmt.Errorf("NS query failed: %v", err)
	}

	var nsRecords []string
	for _, ans := range response.Answer {
		if ns, ok := ans.(*dns.NS); ok {
			nsRecords = append(nsRecords, ns.Ns)
		}
	}

	if len(nsRecords) > 0 {
		return strings.Join(nsRecords, ", "), false, nil // 返回 NS 记录列表
	}

	return "", false, fmt.Errorf("no SOA or NS records found for domain: %s", domain)
}

func lookupSRVWithAD_srv(service string) ([]*dns.SRV, bool, error) {
	// DNS Resolver configuration
	resolverAddr := "8.8.8.8:53" // Google Public DNS
	timeout := 15 * time.Second  // Timeout for DNS query

	// Create a DNS client
	client := &dns.Client{
		Net:     "udp", //
		Timeout: timeout,
	}
	// Create the SRV query
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(service), dns.TypeSRV)
	msg.RecursionDesired = true // Enable recursion
	msg.SetEdns0(4096, true)    // true 表示启用 DO 位，支持 DNSSEC

	// Perform the DNS query
	response, _, err := client.Exchange(msg, resolverAddr)
	if err != nil {
		return nil, false, fmt.Errorf("DNS query failed: %v", err)
	}

	// Check the AD bit in the DNS response flags
	adBit := response.AuthenticatedData
	// 解析 SRV 记录
	var srvRecords []*dns.SRV
	for _, ans := range response.Answer {
		if srv, ok := ans.(*dns.SRV); ok {
			srvRecords = append(srvRecords, srv)
		}
	}
	fmt.Printf("service:%s, adBit:%v\n", service, adBit)
	return srvRecords, adBit, nil
}

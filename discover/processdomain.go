package discover

import (
	"fmt"
	"scan-website/models"
	"scan-website/utils"
	"time"
)

// 处理单个域名
func ProcessDomain(domain string) models.DomainResult {
	domainResult := models.DomainResult{
		Domain:        domain,
		Timestamp:     time.Now().Format(time.RFC3339),
		ErrorMessages: []string{},
	}
	//处理每个域名的一开始就查询CNAME字段
	email := "info@" + domain
	cnameRecords, err := utils.LookupCNAME(domain)
	if err != nil {
		domainResult.ErrorMessages = append(domainResult.ErrorMessages, fmt.Sprintf("CNAME lookup error: %v", err))
	}
	domainResult.CNAME = cnameRecords
	// Autodiscover 查询
	autodiscoverResults := QueryAutodiscover(domain, email)
	domainResult.Autodiscover = autodiscoverResults
	//domainResult.ErrorMessages = append(domainResult.ErrorMessages, errors...)
	// Autoconfig 查询
	autoconfigResults := QueryAutoconfig(domain, email)
	domainResult.Autoconfig = autoconfigResults
	// if err := queryAutoconfig(domain, &result); err != nil {
	// 	result.ErrorMessages = append(result.ErrorMessages, fmt.Sprintf("Autoconfig error: %v", err))
	// }
	// SRV 查询
	srvconfigResults := QuerySRV(domain)
	domainResult.SRV = srvconfigResults
	// if err := querySRV(domain, &result); err != nil {
	// 	result.ErrorMessages = append(result.ErrorMessages, fmt.Sprintf("SRV error: %v", err))
	// }
	//GUESS 9.13
	guessResults := GuessMailServer(domain, 2*time.Second, 20)
	domainResult.GUESS = guessResults

	return domainResult
}

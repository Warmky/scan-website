package discover

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"scan-website/models"
	"scan-website/utils"
	"time"
)

// 查询Autoconfig部分
func QueryAutoconfig(domain string, email string) []models.AutoconfigResult {
	var results []models.AutoconfigResult
	//method1 直接通过url发送get请求得到config
	urls := []string{
		fmt.Sprintf("https://autoconfig.%s/mail/config-v1.1.xml?emailaddress=%s", domain, email),             //uri1
		fmt.Sprintf("https://%s/.well-known/autoconfig/mail/config-v1.1.xml?emailaddress=%s", domain, email), //uri2
		fmt.Sprintf("http://autoconfig.%s/mail/config-v1.1.xml?emailaddress=%s", domain, email),              //uri3
		fmt.Sprintf("http://%s/.well-known/autoconfig/mail/config-v1.1.xml?emailaddress=%s", domain, email),  //uri4
	}
	for i, url := range urls {
		index := i + 1
		config, redirects, certinfo, err := Get_autoconfig_config(domain, url, "directurl", index)

		result := models.AutoconfigResult{
			Domain:    domain,
			Method:    "directurl",
			Index:     index,
			URI:       url,
			Redirects: redirects,
			Config:    config,
			CertInfo:  certinfo,
		}
		if err != nil {
			result.Error = err.Error()
		}
		results = append(results, result)
	}

	//method2 ISPDB
	ISPurl := fmt.Sprintf("https://autoconfig.thunderbird.net/v1.1/%s", domain)
	config, redirects, certinfo, err := Get_autoconfig_config(domain, ISPurl, "ISPDB", 0)
	result_ISPDB := models.AutoconfigResult{
		Domain:    domain,
		Method:    "ISPDB",
		Index:     0,
		URI:       ISPurl,
		Redirects: redirects,
		Config:    config,
		CertInfo:  certinfo,
	}
	if err != nil {
		result_ISPDB.Error = err.Error()
	}
	results = append(results, result_ISPDB)

	//method3 MX查询
	mxHost, err := utils.ResolveMXRecord(domain)
	if err != nil {
		result_MX := models.AutoconfigResult{
			Domain: domain,
			Method: "MX",
			Index:  0,
			Error:  fmt.Sprintf("Resolve MX Record error for %s: %v", domain, err),
		}
		results = append(results, result_MX)
	} else {
		mxFullDomain, mxMainDomain, err := utils.ExtractDomains(mxHost)
		if err != nil {
			result_MX := models.AutoconfigResult{
				Domain: domain,
				Method: "MX",
				Index:  0,
				Error:  fmt.Sprintf("extract domain from mxHost error for %s: %v", domain, err),
			}
			results = append(results, result_MX)
		} else {
			if mxFullDomain == mxMainDomain {
				urls := []string{
					fmt.Sprintf("https://autoconfig.%s/mail/config-v1.1.xml?emailaddress=%s", mxFullDomain, email), //1
					fmt.Sprintf("https://autoconfig.thunderbird.net/v1.1/%s", mxFullDomain),                        //3
				}
				for i, url := range urls {
					config, redirects, certinfo, err := Get_autoconfig_config(domain, url, "MX_samedomain", i*2+1)
					result := models.AutoconfigResult{
						Domain:    domain,
						Method:    "MX_samedomain",
						Index:     i*2 + 1,
						URI:       url,
						Redirects: redirects,
						Config:    config,
						CertInfo:  certinfo,
					}
					if err != nil {
						result.Error = err.Error()
					}
					results = append(results, result)
				}
			} else {
				urls := []string{
					fmt.Sprintf("https://autoconfig.%s/mail/config-v1.1.xml?emailaddress=%s", mxFullDomain, email), //1
					fmt.Sprintf("https://autoconfig.%s/mail/config-v1.1.xml?emailaddress=%s", mxMainDomain, email), //2
					fmt.Sprintf("https://autoconfig.thunderbird.net/v1.1/%s", mxFullDomain),                        //3
					fmt.Sprintf("https://autoconfig.thunderbird.net/v1.1/%s", mxMainDomain),                        //4
				}
				for i, url := range urls {
					config, redirects, certinfo, err := Get_autoconfig_config(domain, url, "MX", i+1)
					result := models.AutoconfigResult{
						Domain:    domain,
						Method:    "MX",
						Index:     i + 1,
						URI:       url,
						Redirects: redirects,
						Config:    config,
						CertInfo:  certinfo,
					}
					if err != nil {
						result.Error = err.Error()
					}
					results = append(results, result)
				}
			}
		}

	}
	return results

}

func Get_autoconfig_config(domain string, url string, method string, index int) (string, []map[string]interface{}, *models.CertInfo, error) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS10,
			},
		},
		Timeout: 15 * time.Second,
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", []map[string]interface{}{}, nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", []map[string]interface{}{}, nil, err
	}
	// 获取重定向历史记录
	redirects := utils.GetRedirects(resp)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", redirects, nil, fmt.Errorf("failed to read response body: %v", err)
	}
	var autoconfigResp models.AutoconfigResponse
	err = xml.Unmarshal(body, &autoconfigResp)
	if err != nil {
		// if (strings.HasPrefix(strings.TrimSpace(string(body)), `<?xml version="1.0"`) || strings.HasPrefix(strings.TrimSpace(string(body)), `<clientConfig`)) && !strings.Contains(strings.TrimSpace(string(body)), `<html`) && !strings.Contains(strings.TrimSpace(string(body)), `<item`) && !strings.Contains(strings.TrimSpace(string(body)), `lastmod`) && !strings.Contains(strings.TrimSpace(string(body)), `lt`) {
		// 	saveno_XMLToFile("no_autoconfig_config.xml", string(body), domain)
		// }
		return "", redirects, nil, fmt.Errorf("failed to unmarshal XML: %v", err)
	} else {
		var certInfo models.CertInfo
		// 提取证书信息
		if resp.TLS != nil {
			//var encodedData []byte
			var encodedCerts []string
			goChain := resp.TLS.PeerCertificates
			endCert := goChain[0]

			// 证书验证
			dnsName := resp.Request.URL.Hostname()
			var VerifyError error
			certInfo.IsTrusted, VerifyError = utils.VerifyCertificate(goChain, dnsName)
			if VerifyError != nil {
				certInfo.VerifyError = VerifyError.Error()
			} else {
				certInfo.VerifyError = ""
			}
			certInfo.IsExpired = endCert.NotAfter.Before(time.Now())
			certInfo.IsHostnameMatch = utils.VerifyHostname(endCert, dnsName)
			certInfo.IsSelfSigned = utils.IsSelfSigned(endCert)
			certInfo.IsInOrder = utils.IsChainInOrder(goChain)
			certInfo.TLSVersion = resp.TLS.Version

			// 提取证书的其他信息
			certInfo.Subject = endCert.Subject.CommonName
			certInfo.Issuer = endCert.Issuer.String()
			certInfo.SignatureAlg = endCert.SignatureAlgorithm.String()
			certInfo.AlgWarning = utils.AlgWarnings(endCert)

			// 将证书编码为 base64 格式
			for _, cert := range goChain {
				encoded := base64.StdEncoding.EncodeToString(cert.Raw)
				//encodedData = append(encodedData, []byte(encoded)...)
				encodedCerts = append(encodedCerts, encoded)
			}
			//certInfo.RawCert = encodedData
			certInfo.RawCerts = encodedCerts

		}

		config := string(body)
		// outputfile := fmt.Sprintf("./autoconfig/autoconfig_%s_%d.xml", method, index) //12.18 用Index加以区分
		// err = saveXMLToFile_autoconfig(outputfile, config, domain)
		// if err != nil {
		// 	return "", redirects, &certInfo, err
		// }
		return config, redirects, &certInfo, nil
	}
}

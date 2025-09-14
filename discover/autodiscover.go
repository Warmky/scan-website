package discover

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"scan-website/models"
	"scan-website/utils"
	"time"
)

func QueryAutodiscover(domain string, email string) []models.AutodiscoverResult {
	var results []models.AutodiscoverResult
	// //查询autodiscover.example.com的cname记录
	// autodiscover_prefixadd := "autodiscover." + domain
	// autodiscover_cnameRecords, _ := lookupCNAME(autodiscover_prefixadd)
	// method1:直接通过text manipulation，直接发出post请求
	uris := []string{
		fmt.Sprintf("http://%s/autodiscover/autodiscover.xml", domain),
		fmt.Sprintf("https://autodiscover.%s/autodiscover/autodiscover.xml", domain),
		fmt.Sprintf("http://autodiscover.%s/autodiscover/autodiscover.xml", domain),
		fmt.Sprintf("https://%s/autodiscover/autodiscover.xml", domain),
	}
	for i, uri := range uris {
		index := i + 1
		flag1, flag2, flag3, redirects, config, certinfo, err := getAutodiscoverConfig(domain, uri, email, "post", index, 0, 0, 0) //getAutodiscoverConfig照常
		fmt.Printf("flag1: %d\n", flag1)
		fmt.Printf("flag2: %d\n", flag2)
		fmt.Printf("flag3: %d\n", flag3)

		result := models.AutodiscoverResult{
			Domain:    domain,
			Method:    "POST",
			Index:     index,
			URI:       uri,
			Redirects: redirects,
			Config:    config,
			CertInfo:  certinfo,
		}
		if err != nil {
			result.Error = err.Error()
		}
		results = append(results, result)
	}

	//method2:通过dns找到server,再post请求
	service := "_autodiscover._tcp." + domain
	uriDNS, _, err := utils.LookupSRVWithAD_autodiscover(domain) //
	if err != nil {
		result_srv := models.AutodiscoverResult{
			Domain: domain,
			Method: "srv-post",
			Index:  0,
			Error:  fmt.Sprintf("Failed to lookup SRV records for %s: %v", service, err),
		}
		results = append(results, result_srv)
	} else {
		//record_ADbit_SRV_autodiscover("autodiscover_record_ad_srv.txt", domain, adBit)
		_, _, _, redirects, config, certinfo, err1 := getAutodiscoverConfig(domain, uriDNS, email, "srv-post", 0, 0, 0, 0)
		result_srv := models.AutodiscoverResult{
			Domain:    domain,
			Method:    "srv-post",
			Index:     0,
			Redirects: redirects,
			Config:    config,
			CertInfo:  certinfo,
			//AutodiscoverCNAME: autodiscover_cnameRecords,
		}
		if err1 != nil {
			result_srv.Error = err1.Error()
		}
		results = append(results, result_srv)
	}

	//method3：先GET找到server，再post请求
	getURI := fmt.Sprintf("http://autodiscover.%s/autodiscover/autodiscover.xml", domain) //是通过这个getURI得到server的uri，然后再进行post请求10.26
	redirects, config, certinfo, err := GET_AutodiscoverConfig(domain, getURI, email)     //一开始的get请求返回的不是重定向的没有管
	result_GET := models.AutodiscoverResult{
		Domain:    domain,
		Method:    "get-post",
		Index:     0,
		URI:       getURI,
		Redirects: redirects,
		Config:    config,
		CertInfo:  certinfo,
		//AutodiscoverCNAME: autodiscover_cnameRecords,
	}
	if err != nil {
		result_GET.Error = err.Error()
	} //TODO:len(redirect)>0?
	results = append(results, result_GET)

	//method4:增加几条直接GET请求的路径
	direct_getURIs := []string{
		fmt.Sprintf("http://%s/autodiscover/autodiscover.xml", domain),               //uri1
		fmt.Sprintf("https://autodiscover.%s/autodiscover/autodiscover.xml", domain), //2
		fmt.Sprintf("http://autodiscover.%s/autodiscover/autodiscover.xml", domain),  //3
		fmt.Sprintf("https://%s/autodiscover/autodiscover.xml", domain),              //4
	}
	for i, direct_getURI := range direct_getURIs {
		index := i + 1
		_, _, _, redirects, config, certinfo, err := direct_GET_AutodiscoverConfig(domain, direct_getURI, email, "get", index, 0, 0, 0)
		result := models.AutodiscoverResult{
			Domain:    domain,
			Method:    "direct_get",
			Index:     index,
			URI:       direct_getURI,
			Redirects: redirects,
			Config:    config,
			CertInfo:  certinfo,
			//AutodiscoverCNAME: autodiscover_cnameRecords,
		}
		if err != nil {
			result.Error = err.Error()
		}
		results = append(results, result)
	}

	return results
}

func getAutodiscoverConfig(origin_domain string, uri string, email_add string, method string, index int, flag1 int, flag2 int, flag3 int) (int, int, int, []map[string]interface{}, string, *models.CertInfo, error) {
	xmlRequest := fmt.Sprintf(`
		<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">
			<Request>
				<EMailAddress>%s</EMailAddress>
				<AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>
			</Request>
		</Autodiscover>`, email_add)

	req, err := http.NewRequest("POST", uri, bytes.NewBufferString(xmlRequest))
	if err != nil {
		fmt.Printf("Error creating request for %s: %v\n", uri, err)
		return flag1, flag2, flag3, []map[string]interface{}{}, "", nil, fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "text/xml")
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS10,
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // 禁止重定向
		},
		Timeout: 15 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error sending request to %s: %v\n", uri, err)
		return flag1, flag2, flag3, []map[string]interface{}{}, "", nil, fmt.Errorf("failed to send request: %v", err)
	}

	redirects := utils.GetRedirects(resp) // 获取当前重定向链
	defer resp.Body.Close()               //
	if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusMovedPermanently {
		// 处理重定向
		flag1 = flag1 + 1
		fmt.Printf("flag1now:%d\n", flag1)
		location := resp.Header.Get("Location")
		fmt.Printf("Redirect to: %s\n", location)
		if location == "" {
			return flag1, flag2, flag3, redirects, "", nil, fmt.Errorf("missing Location header in redirect")
		} else if flag1 > 10 { //12.27限制重定向次数
			//saveXMLToFile_autodiscover("./location.xml", origin_domain, email_add)
			return flag1, flag2, flag3, redirects, "", nil, fmt.Errorf("too many redirect times")
		}

		newURI, err := url.Parse(location)
		if err != nil {
			return flag1, flag2, flag3, redirects, "", nil, fmt.Errorf("failed to parse redirect URL: %s", location)
		}

		// 递归调用并合并重定向链
		newflag1, newflag2, newflag3, nextRedirects, result, certinfo, err := getAutodiscoverConfig(origin_domain, newURI.String(), email_add, method, index, flag1, flag2, flag3)
		//return append(redirects, nextRedirects...), result, err //12.27原
		return newflag1, newflag2, newflag3, append(redirects, nextRedirects...), result, certinfo, err
	} else if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		// 处理成功响应
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return flag1, flag2, flag3, redirects, "", nil, fmt.Errorf("failed to read response body: %v", err)
		}

		var autodiscoverResp models.AutodiscoverResponse
		err = xml.Unmarshal(body, &autodiscoverResp)
		//这里先记录下unmarshal就不成功的xml
		if err != nil {
			// if (strings.HasPrefix(strings.TrimSpace(string(body)), `<?xml version="1.0"`) || strings.HasPrefix(strings.TrimSpace(string(body)), `<Autodiscover`)) && !strings.Contains(strings.TrimSpace(string(body)), `<html`) && !strings.Contains(strings.TrimSpace(string(body)), `<item`) && !strings.Contains(strings.TrimSpace(string(body)), `lastmod`) && !strings.Contains(strings.TrimSpace(string(body)), `lt`) {
			// 	//if !strings.Contains(strings.TrimSpace(string(body)), `<html`) && !strings.Contains(strings.TrimSpace(string(body)), `<item`) && !strings.Contains(strings.TrimSpace(string(body)), `lastmod`) && !strings.Contains(strings.TrimSpace(string(body)), `lt`) {
			// 	//saveno_XMLToFile("no_autodiscover_config.xml", string(body), email_add)
			// } //记录错误格式的xml
			return flag1, flag2, flag3, redirects, "", nil, fmt.Errorf("failed to unmarshal XML: %v", err)
		}

		// 处理 redirectAddr 和 redirectUrl
		if autodiscoverResp.Response.Account.Action == "redirectAddr" {
			flag2 = flag2 + 1
			newEmail := autodiscoverResp.Response.Account.RedirectAddr
			//record_filename := filepath.Join("./autodiscover/records", "ReAddr.xml")
			//saveXMLToFile_with_ReAdrr_autodiscover(record_filename, string(body), email_add)
			if newEmail != "" && flag2 <= 10 {
				newflag1, newflag2, newflag3, nextRedirects, result, certinfo, err := getAutodiscoverConfig(origin_domain, uri, newEmail, method, index, flag1, flag2, flag3)
				return newflag1, newflag2, newflag3, append(redirects, nextRedirects...), result, certinfo, err
			} else if newEmail != "" { //12.27
				//saveXMLToFile_autodiscover("./flag2.xml", origin_domain, email_add)
				return flag1, flag2, flag3, redirects, "", nil, fmt.Errorf("too many RedirectAddr")
			} else {
				return flag1, flag2, flag3, redirects, "", nil, fmt.Errorf("nil ReAddr")
			}
		} else if autodiscoverResp.Response.Account.Action == "redirectUrl" {
			flag3 = flag3 + 1
			newUri := autodiscoverResp.Response.Account.RedirectUrl
			//record_filename := filepath.Join("./autodiscover/records", "Reurl.xml")
			//saveXMLToFile_with_Reuri_autodiscover(record_filename, string(body), email_add)
			if newUri != "" && flag3 <= 10 {
				newflag1, newflag2, newflag3, nextRedirects, result, certinfo, err := getAutodiscoverConfig(origin_domain, newUri, email_add, method, index, flag1, flag2, flag3)
				return newflag1, newflag2, newflag3, append(redirects, nextRedirects...), result, certinfo, err
			} else if newUri != "" {
				//saveXMLToFile_autodiscover("./flag3.xml", origin_domain, email_add)
				return flag1, flag2, flag3, redirects, "", nil, fmt.Errorf("too many RedirectUrl")
			} else {
				return flag1, flag2, flag3, redirects, "", nil, fmt.Errorf("nil Reuri")
			}
		} else if autodiscoverResp.Response.Account.Action == "settings" { //这才是我们需要的
			// 记录并返回成功配置(3.13修改，因为会将Response命名空间不合规的也解析到这里)
			// outputfile := fmt.Sprintf("./autodiscover/autodiscover_%s_%d_config.xml", method, index)
			// saveXMLToFile_autodiscover(outputfile, string(body), email_add)

			//只在可以直接返回xml配置的时候记录证书信息
			var certInfo models.CertInfo
			// 提取证书信息
			if resp.TLS != nil {
				//var encodedData []byte //8.15
				var encodedCerts []string //8.15
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
					//encodedData = append(encodedData, []byte(encoded)...)//8.16
					encodedCerts = append(encodedCerts, encoded)
				}
				//certInfo.RawCert = encodedData //8.15
				certInfo.RawCerts = encodedCerts
			}
			return flag1, flag2, flag3, redirects, string(body), &certInfo, nil
		} else if autodiscoverResp.Response.Error != nil {
			//fmt.Printf("Error: %s\n", string(body))
			// 处理错误响应
			errorConfig := fmt.Sprintf("Errorcode:%d-%s\n", autodiscoverResp.Response.Error.ErrorCode, autodiscoverResp.Response.Error.Message)
			//outputfile := fmt.Sprintf("./autodiscover/autodiscover_%s_%d_Errorconfig.txt", method, index)
			//saveXMLToFile_autodiscover(outputfile, errorConfig, email_add)
			return flag1, flag2, flag3, redirects, errorConfig, nil, nil
		} else {
			//fmt.Printf("Response element not valid:%s\n", string(body))
			//处理Response可能本身就不正确的响应,同时也会存储不合规的xml(unmarshal的时候合规但Response不合规)
			alsoErrorConfig := fmt.Sprintf("Non-valid Response element for %s\n:", email_add)
			//outputfile := fmt.Sprintf("./autodiscover/autodiscover_%s_%d_AlsoErrorConfig.xml", method, index)
			//saveXMLToFile_autodiscover(outputfile, string(body), email_add)
			return flag1, flag2, flag3, redirects, alsoErrorConfig, nil, nil
		}
	} else {
		// 处理非成功响应
		//outputfile := fmt.Sprintf("./autodiscover/autodiscover_%s_%d_badresponse.txt", method, index)
		badResponse := fmt.Sprintf("Bad response for %s: %d\n", email_add, resp.StatusCode)
		//saveXMLToFile_autodiscover(outputfile, badResponse, email_add)
		return flag1, flag2, flag3, redirects, badResponse, nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}
func GET_AutodiscoverConfig(origin_domain string, uri string, email_add string) ([]map[string]interface{}, string, *models.CertInfo, error) { //使用先get后post方法
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS10,
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // 禁止重定向
		},
		Timeout: 15 * time.Second,
	}
	resp, err := client.Get(uri)
	if err != nil {
		return []map[string]interface{}{}, "", nil, fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	redirects := utils.GetRedirects(resp) // 获取当前重定向链

	if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusMovedPermanently { //仅通过get请求获取重定向地址
		location := resp.Header.Get("Location")
		fmt.Printf("Redirect to: %s\n", location)
		if location == "" {
			return nil, "", nil, fmt.Errorf("missing Location header in redirect")
		}
		newURI, err := url.Parse(location)
		if err != nil {
			return nil, "", nil, fmt.Errorf("failed to parse redirect URL: %s", location)
		}

		// 递归调用并合并重定向链
		_, _, _, nextRedirects, result, certinfo, err := getAutodiscoverConfig(origin_domain, newURI.String(), email_add, "get_post", 0, 0, 0, 0)
		return append(redirects, nextRedirects...), result, certinfo, err
	} else {
		return nil, "", nil, fmt.Errorf("not find Redirect Statuscode")
	}
}

func direct_GET_AutodiscoverConfig(origin_domain string, uri string, email_add string, method string, index int, flag1 int, flag2 int, flag3 int) (int, int, int, []map[string]interface{}, string, *models.CertInfo, error) { //一路get请求
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS10,
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // 禁止重定向
		},
		Timeout: 15 * time.Second, // 设置请求超时时间
	}
	resp, err := client.Get(uri)
	if err != nil {
		return flag1, flag2, flag3, []map[string]interface{}{}, "", nil, fmt.Errorf("failed to send request: %v", err)
	}

	redirects := utils.GetRedirects(resp)
	defer resp.Body.Close() //

	if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusMovedPermanently {
		flag1 = flag1 + 1
		location := resp.Header.Get("Location")
		fmt.Printf("Redirect to: %s\n", location)
		if location == "" {
			return flag1, flag2, flag3, redirects, "", nil, fmt.Errorf("missing Location header in redirect")
		} else if flag1 > 10 {
			//saveXMLToFile_autodiscover("./location2.xml", origin_domain, email_add)
			return flag1, flag2, flag3, redirects, "", nil, fmt.Errorf("too many redirect times")
		}

		newURI, err := url.Parse(location)
		if err != nil {
			return flag1, flag2, flag3, redirects, "", nil, fmt.Errorf("failed to parse redirect URL: %s", location)
		}

		// 递归调用并合并重定向链
		newflag1, newflag2, newflag3, nextRedirects, result, certinfo, err := direct_GET_AutodiscoverConfig(origin_domain, newURI.String(), email_add, method, index, flag1, flag2, flag3)
		return newflag1, newflag2, newflag3, append(redirects, nextRedirects...), result, certinfo, err
	} else if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return flag1, flag2, flag3, redirects, "", nil, fmt.Errorf("failed to read response body: %v", err)
		}
		var autodiscoverResp models.AutodiscoverResponse
		err = xml.Unmarshal(body, &autodiscoverResp)
		if err != nil {
			// if (strings.HasPrefix(strings.TrimSpace(string(body)), `<?xml version="1.0"`) || strings.HasPrefix(strings.TrimSpace(string(body)), `<Autodiscover`)) && !strings.Contains(strings.TrimSpace(string(body)), `<html`) && !strings.Contains(strings.TrimSpace(string(body)), `<item`) && !strings.Contains(strings.TrimSpace(string(body)), `lastmod`) && !strings.Contains(strings.TrimSpace(string(body)), `lt`) {
			// 	//if !strings.Contains(strings.TrimSpace(string(body)), `<html`) && !strings.Contains(strings.TrimSpace(string(body)), `<item`) && !strings.Contains(strings.TrimSpace(string(body)), `lastmod`) && !strings.Contains(strings.TrimSpace(string(body)), `lt`) {
			// 	saveno_XMLToFile("no_autodiscover_config_directget.xml", string(body), email_add)
			// } //记录错误格式的xml
			return flag1, flag2, flag3, redirects, "", nil, fmt.Errorf("failed to unmarshal XML: %v", err)
		}
		if autodiscoverResp.Response.Account.Action == "redirectAddr" {
			flag2 = flag2 + 1
			newEmail := autodiscoverResp.Response.Account.RedirectAddr
			//outputfile := fmt.Sprintf("./autodiscover/autodiscover_%s_%d_redirectAddr_config.xml", method, index)
			//saveXMLToFile_autodiscover(outputfile, string(body), email_add)
			if newEmail != "" {
				return flag1, flag2, flag3, redirects, string(body), nil, nil //TODO, 这里直接返回带redirect_email了
			} else {
				return flag1, flag2, flag3, redirects, "", nil, fmt.Errorf("nil ReAddr")
			}
		} else if autodiscoverResp.Response.Account.Action == "redirectUrl" {
			flag3 = flag3 + 1
			newUri := autodiscoverResp.Response.Account.RedirectUrl
			//record_filename := filepath.Join("./autodiscover/records", "Reurl_dirGET.xml")
			//saveXMLToFile_with_Reuri_autodiscover(record_filename, string(body), email_add) //记录redirecturi,是否会出现继续reUri?
			if newUri != "" && flag3 <= 10 {
				newflag1, newflag2, newflag3, nextRedirects, result, certinfo, err := direct_GET_AutodiscoverConfig(origin_domain, newUri, email_add, method, index, flag1, flag2, flag3)
				return newflag1, newflag2, newflag3, append(redirects, nextRedirects...), result, certinfo, err
			} else if newUri != "" {
				//saveXMLToFile_autodiscover("./flag32.xml", origin_domain, email_add)
				return flag1, flag2, flag3, redirects, "", nil, fmt.Errorf("too many RedirectUrl")
			} else {
				return flag1, flag2, flag3, redirects, "", nil, fmt.Errorf("nil Reurl")
			}
		} else if autodiscoverResp.Response.Account.Action == "settings" {
			//outputfile := fmt.Sprintf("./autodiscover/autodiscover_%s_%d_config.xml", method, index)
			//saveXMLToFile_autodiscover(outputfile, string(body), email_add)
			//只在可以直接返回xml配置的时候记录证书信息
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
			return flag1, flag2, flag3, redirects, string(body), &certInfo, nil
		} else if autodiscoverResp.Response.Error != nil {
			//fmt.Printf("Error: %s\n", string(body))
			// 处理错误响应
			errorConfig := fmt.Sprintf("Errorcode:%d-%s\n", autodiscoverResp.Response.Error.ErrorCode, autodiscoverResp.Response.Error.Message)
			//outputfile := fmt.Sprintf("./autodiscover/autodiscover_%s_%d_Errorconfig.txt", method, index)
			//saveXMLToFile_autodiscover(outputfile, errorConfig, email_add)
			return flag1, flag2, flag3, redirects, errorConfig, nil, nil
		} else {
			//fmt.Printf("Response element not valid:%s\n", string(body))
			//处理Response可能本身就不正确的响应,同时也会存储不合规的xml(unmarshal的时候合规但Response不合规)
			alsoErrorConfig := fmt.Sprintf("Non-valid Response element for %s\n:", email_add)
			//outputfile := fmt.Sprintf("./autodiscover/autodiscover_%s_%d_AlsoErrorConfig.xml", method, index)
			//saveXMLToFile_autodiscover(outputfile, string(body), email_add)
			return flag1, flag2, flag3, redirects, alsoErrorConfig, nil, nil
		}
	} else {
		//outputfile := fmt.Sprintf("./autodiscover/autodiscover_%s_%d_badresponse.txt", method, index)
		bad_response := fmt.Sprintf("Bad response for %s:%d\n", email_add, resp.StatusCode)
		//saveXMLToFile_autodiscover(outputfile, bad_response, email_add)
		return flag1, flag2, flag3, redirects, bad_response, nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode) //同时也想记录请求发送失败时的状态码
	}
}

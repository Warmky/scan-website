package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"scan-website/models"
	"scan-website/utils"
)

type JSONLRecord struct {
	IP       string                 `json:"ip"`
	Domain   string                 `json:"domain"`
	Data     map[string]interface{} `json:"data"`
	CertInfo *models.CertInfo       `json:"cert_info,omitempty"`
	TLSVer   string                 `json:"tls_version,omitempty"`
}

func main() {
	inFile, err := os.Open("pop3s-995_pop3s.jsonl")
	if err != nil {
		panic(err)
	}
	defer inFile.Close()

	outFile, err := os.Create("pop3s-995_pop3s_with_cert.jsonl")
	if err != nil {
		panic(err)
	}
	defer outFile.Close()

	scanner := bufio.NewScanner(inFile)
	writer := bufio.NewWriter(outFile)
	defer writer.Flush()

	for scanner.Scan() {
		line := scanner.Text()
		var rec JSONLRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			fmt.Println("parse error:", err)
			continue
		}

		for _, protoData := range rec.Data {
			protoMap, ok := protoData.(map[string]interface{})
			if !ok {
				continue
			}
			status, _ := protoMap["status"].(string)
			if status != "success" {
				continue
			}

			result, ok := protoMap["result"].(map[string]interface{})
			if !ok {
				continue
			}
			tlsData, ok := result["tls"].(map[string]interface{})
			if !ok {
				continue
			}

			// 记录 TLS 版本
			if handshake, ok := tlsData["handshake_log"].(map[string]interface{}); ok {
				if serverHello, ok := handshake["server_hello"].(map[string]interface{}); ok {
					if version, ok := serverHello["version"].(map[string]interface{}); ok {
						if name, ok := version["name"].(string); ok {
							rec.TLSVer = name
						}
					}
				}
			}

			// 解析证书链
			serverCerts, ok := tlsData["server_certificates"].(map[string]interface{})
			if !ok {
				continue
			}
			chainList, ok := serverCerts["chain"].([]interface{})
			if !ok {
				continue
			}

			var goChain []*utils.Certificate
			var rawCerts []string

			for _, certItem := range chainList {
				certMap, ok := certItem.(map[string]interface{})
				if !ok {
					continue
				}
				rawStr, _ := certMap["raw"].(string)
				certBytes, err := base64.StdEncoding.DecodeString(rawStr)
				if err != nil {
					fmt.Println("base64 decode error:", err)
					continue
				}
				x509Cert, err := utils.ParseCert(certBytes)
				if err != nil {
					fmt.Println("parse cert error:", err)
					continue
				}
				goChain = append(goChain, x509Cert)
				rawCerts = append(rawCerts, base64.StdEncoding.EncodeToString(certBytes))
			}

			if len(goChain) == 0 {
				continue
			}

			endCert := goChain[0]
			certInfo := models.CertInfo{}
			dnsName := rec.Domain

			var verifyErr error
			certInfo.IsTrusted, verifyErr = utils.VerifyCertificate(goChain, dnsName)
			if verifyErr != nil {
				certInfo.VerifyError = verifyErr.Error()
			} else {
				certInfo.VerifyError = ""
			}

			certInfo.IsExpired = endCert.NotAfter.Before(time.Now())
			certInfo.IsHostnameMatch = utils.VerifyHostname(endCert, dnsName)
			certInfo.IsSelfSigned = utils.IsSelfSigned(endCert)
			certInfo.IsInOrder = utils.IsChainInOrder(goChain)
			certInfo.TLSVersion = rec.TLSVer
			certInfo.Subject = endCert.Subject.CommonName
			certInfo.Issuer = endCert.Issuer.String()
			certInfo.SignatureAlg = endCert.SignatureAlgorithm.String()
			certInfo.AlgWarning = utils.AlgWarnings(endCert)
			certInfo.RawCerts = rawCerts

			rec.CertInfo = &certInfo
		}

		outBytes, _ := json.Marshal(rec)
		writer.Write(outBytes)
		writer.Write([]byte("\n"))
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("scanner error:", err)
	}
}

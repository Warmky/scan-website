package measurement

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"crypto/x509"
	"scan-website/utils"
)

// ---------------- zgrab2 JSON 结构 ----------------
type ZGrabResult struct {
	IP   string `json:"ip"`
	Host string `json:"host"`
	Data struct {
		StartTLS struct {
			TLS struct {
				Certificate struct {
					CertificateChain []string `json:"certificate_chain"`
				} `json:"certificate"`
			} `json:"tls"`
		} `json:"starttls"`
	} `json:"data"`
}

func PemDecode(data []byte) (*pem.Block, []byte) {
	return pem.Decode(data)
}

// ---------------- 辅助函数 ----------------
func parseCertChain(pemList []string) ([]*x509.Certificate, error) {
	certs := []*x509.Certificate{}
	for _, pemStr := range pemList {
		block, _ := PemDecode([]byte(pemStr))
		if block == nil {
			return nil, fmt.Errorf("failed to decode PEM")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// ---------------- 主函数 ----------------
func Certvr() {
	inputFile := "/home/wzq/scan-website/zgrab2/real/imap-993_imaps.jsonl" // JSONL 输入
	outputFile := "/home/wzq/scan-website/cmd/certreal/cert_verify.csv"    // CSV 输出

	inFile, err := os.Open(inputFile)
	if err != nil {
		panic(err)
	}
	defer inFile.Close()

	outFile, err := os.Create(outputFile)
	if err != nil {
		panic(err)
	}
	defer outFile.Close()

	writer := csv.NewWriter(outFile)
	defer writer.Flush()

	// 写入 CSV header
	writer.Write([]string{
		"IP", "Host", "VerifyOK", "SelfSigned", "ChainInOrder", "AlgWarnings",
	})

	scanner := bufio.NewScanner(inFile)
	for scanner.Scan() {
		line := scanner.Text()
		var result ZGrabResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			fmt.Println("JSON unmarshal failed:", err)
			continue
		}

		pemChain := result.Data.StartTLS.TLS.Certificate.CertificateChain
		if len(pemChain) == 0 {
			continue
		}

		chain, err := parseCertChain(pemChain)
		if err != nil {
			fmt.Println(result.Host, "parse cert chain failed:", err)
			continue
		}

		// 验证证书链
		verifyOK, _ := utils.VerifyCertificate(chain, result.Host)
		selfSigned := utils.IsSelfSigned(chain[0])
		chainOrder := utils.IsChainInOrder(chain)

		// 算法警告汇总
		var warnings []string
		for _, c := range chain {
			w := utils.AlgWarnings(c)
			if w != "" {
				warnings = append(warnings, w)
			}
		}

		writer.Write([]string{
			result.IP,
			result.Host,
			fmt.Sprintf("%v", verifyOK),
			fmt.Sprintf("%v", selfSigned),
			chainOrder,
			strings.Join(warnings, "; "),
		})
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Scanner error:", err)
	}

	fmt.Println("Done! Output written to", outputFile)
}

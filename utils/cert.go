package utils

import (
	"bytes"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"os"
	"strconv"

	"github.com/zakjan/cert-chain-resolver/certUtil"
)

// 证书解析验证相关函数
func VerifyCertificate(chain []*x509.Certificate, domain string) (bool, error) {
	if len(chain) == 1 {
		temp_chain, err := certUtil.FetchCertificateChain(chain[0])
		if err != nil {
			//log.Println("failed to fetch certificate chain")
			return false, fmt.Errorf("failed to fetch certificate chain:%v", err)
		}
		chain = temp_chain
	}

	intermediates := x509.NewCertPool()
	for i := 1; i < len(chain); i++ {
		intermediates.AddCert(chain[i])
	}

	certPool := x509.NewCertPool()
	pemFile := "/home/wzq/scan-website/IncludedRootsPEM313.txt" //修改获取roots的途径
	pem, err := os.ReadFile(pemFile)
	if err != nil {
		//log.Println("failed to read root certificate")
		return false, fmt.Errorf("failed to read root certificate:%v", err)
	}
	ok := certPool.AppendCertsFromPEM(pem)
	if !ok {
		//log.Println("failed to import root certificate")
		return false, fmt.Errorf("failed to import root certificate:%v", err)
	}

	opts := x509.VerifyOptions{
		Roots:         certPool,
		Intermediates: intermediates,
		DNSName:       domain,
	}

	if _, err := chain[0].Verify(opts); err != nil {
		//fmt.Println(err)
		return false, fmt.Errorf("certificate verify failed: %v", err)
	}

	return true, nil
}

func VerifyHostname(cert *x509.Certificate, domain string) bool {
	return cert.VerifyHostname(domain) == nil
}

// Ref to: https://github.com/izolight/certigo/blob/v1.10.0/lib/encoder.go#L445
func IsSelfSigned(cert *x509.Certificate) bool {
	if bytes.Equal(cert.RawIssuer, cert.RawSubject) {
		return true
	} //12.25
	return cert.CheckSignatureFrom(cert) == nil
}

// Ref to: https://github.com/google/certificate-transparency-go/blob/master/ctutil/sctcheck/sctcheck.go
func IsChainInOrder(chain []*x509.Certificate) string {
	// var issuer *x509.Certificate
	leaf := chain[0]
	for i := 1; i < len(chain); i++ {
		c := chain[i]
		if bytes.Equal(c.RawSubject, leaf.RawIssuer) && c.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature) == nil {
			// issuer = c
			if i > 1 {
				return "not"
			}
			break
		}
	}
	if len(chain) < 1 {
		return "single"
	}
	return "yes"
}

var algoName = [...]string{
	x509.MD2WithRSA:      "MD2-RSA",
	x509.MD5WithRSA:      "MD5-RSA",
	x509.SHA1WithRSA:     "SHA1-RSA",
	x509.SHA256WithRSA:   "SHA256-RSA",
	x509.SHA384WithRSA:   "SHA384-RSA",
	x509.SHA512WithRSA:   "SHA512-RSA",
	x509.DSAWithSHA1:     "DSA-SHA1",
	x509.DSAWithSHA256:   "DSA-SHA256",
	x509.ECDSAWithSHA1:   "ECDSA-SHA1",
	x509.ECDSAWithSHA256: "ECDSA-SHA256",
	x509.ECDSAWithSHA384: "ECDSA-SHA384",
	x509.ECDSAWithSHA512: "ECDSA-SHA512",
}

var badSignatureAlgorithms = [...]x509.SignatureAlgorithm{
	x509.MD2WithRSA,
	x509.MD5WithRSA,
	x509.SHA1WithRSA,
	x509.DSAWithSHA1,
	x509.ECDSAWithSHA1,
}

func AlgWarnings(cert *x509.Certificate) (warning string) {
	alg, size := decodeKey(cert.PublicKey)
	if (alg == "RSA" || alg == "DSA") && size < 2048 {
		// warnings = append(warnings, fmt.Sprintf("Size of %s key should be at least 2048 bits", alg))
		warning = fmt.Sprintf("Size of %s key should be at least 2048 bits", alg)
	}
	if alg == "ECDSA" && size < 224 {
		warning = fmt.Sprintf("Size of %s key should be at least 224 bits", alg)
	}

	for _, alg := range badSignatureAlgorithms {
		if cert.SignatureAlgorithm == alg {
			warning = fmt.Sprintf("Signed with %s, which is an outdated signature algorithm", algString(alg))
		}
	}

	if alg == "RSA" {
		key := cert.PublicKey.(*rsa.PublicKey)
		if key.E < 3 {
			warning = "Public key exponent in RSA key is less than 3"
		}
		if key.N.Sign() != 1 {
			warning = "Public key modulus in RSA key appears to be zero/negative"
		}
	}

	return warning
}

// decodeKey returns the algorithm and key size for a public key.
func decodeKey(publicKey interface{}) (string, int) {
	switch publicKey.(type) {
	case *dsa.PublicKey:
		return "DSA", publicKey.(*dsa.PublicKey).P.BitLen()
	case *ecdsa.PublicKey:
		return "ECDSA", publicKey.(*ecdsa.PublicKey).Curve.Params().BitSize
	case *rsa.PublicKey:
		return "RSA", publicKey.(*rsa.PublicKey).N.BitLen()
	default:
		return "", 0
	}
}

func algString(algo x509.SignatureAlgorithm) string {
	if 0 < algo && int(algo) < len(algoName) {
		return algoName[algo]
	}
	return strconv.Itoa(int(algo))
}

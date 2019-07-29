package plugin

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"software.sslmate.com/src/go-pkcs12"
)

func BuildPkcs12(certPEM, keyPEM, caPEMs string) ([]byte, error) {
	keyPair, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		return nil, err
	}

	caCerts, err := parseCAs(caPEMs)
	if err != nil {
		return nil, err
	}

	return pkcs12.Encode(rand.Reader, keyPair.PrivateKey, cert, caCerts, pkcs12.DefaultPassword)
}

func parseCAs(caPEMs string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	remaining := []byte(caPEMs)
	for len(remaining) > 0 {
		var block *pem.Block
		block, remaining = pem.Decode(remaining)
		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}

		certs = append(certs, cert)
	}

	return certs, nil
}

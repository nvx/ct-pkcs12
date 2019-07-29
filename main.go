package main

import (
	"encoding/json"
	"github.com/nvx/ct-pkcs12/plugin"
	"log"
	"os"
)

func main() {
	// ct-pkcs12 <out.p12> <cert pem as JSON> <key pem as JSON> [ca pem as JSON]...
	if len(os.Args) < 4 {
		log.Fatal("Not enough parameters")
	}

	outFile := os.Args[1]

	var certPEM, keyPEM, caPEMs string
	err := json.Unmarshal([]byte(os.Args[2]), &certPEM)
	if err != nil {
		log.Fatal(err)
	}

	err = json.Unmarshal([]byte(os.Args[3]), &keyPEM)
	if err != nil {
		log.Fatal(err)
	}

	for _, arg := range os.Args[4:] {
		var caPEM string
		err = json.Unmarshal([]byte(arg), &caPEM)
		if err != nil {
			log.Fatal(err)
		}

		if caPEMs != "" {
			caPEMs += "\n"
		}

		caPEMs += caPEM
	}

	if certPEM == "" || keyPEM == "" {
		// no-op for empty input
		return
	}

	p12, err := plugin.BuildPkcs12(certPEM, keyPEM, caPEMs)
	if err != nil {
		log.Fatal(err)
	}

	err = plugin.WriteFile(outFile, p12)
	if err != nil {
		log.Fatal(err)
	}
}

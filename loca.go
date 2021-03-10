// Copyright (c) 2021 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"time"
)

const (
	dateFormat = "2006-01-02"
	defaultAge = time.Hour * 123456
)

const usage = `Very simple Ed25519 client certificate creation utility.

Initialize a certificate authority:
  %s -init [-cacert=file -cakey=file] [not-after]

Generate a client certificate:
  %s cert-file key-file common-name [not-after]

Do both at the same time:
  %s -init [-cacert=file -cakey=file] cert-file key-file common-name [not-after]

The not-after date is specified in YYYY-MM-DD format.

Flags:
`

func main() {
	log.SetFlags(0)

	flag.Usage = func() {
		prog := os.Args[0]
		fmt.Fprintf(flag.CommandLine.Output(), usage, prog, prog, prog)
		flag.PrintDefaults()
	}

	var (
		ca     bool
		caCert = "cacert.pem"
		caKey  = "cakey.pem"
	)

	flag.BoolVar(&ca, "init", ca, "generate CA certificate and private key")
	flag.StringVar(&caCert, "cacert", caCert, "CA certificate filename")
	flag.StringVar(&caKey, "cakey", caKey, "CA private key filename")
	flag.Parse()

	var (
		client   bool
		cert     string
		key      string
		name     string
		notAfter string
	)

	switch flag.NArg() {
	case 0:

	case 1:
		notAfter = flag.Arg(0)

	case 3:
		client = true
		cert = flag.Arg(0)
		key = flag.Arg(1)
		name = flag.Arg(2)

	case 4:
		client = true
		cert = flag.Arg(0)
		key = flag.Arg(1)
		name = flag.Arg(2)
		notAfter = flag.Arg(3)

	default:
		flag.Usage()
		os.Exit(2)
	}

	if !(ca || client) {
		flag.Usage()
		os.Exit(2)
	}

	var t time.Time
	var err error

	if notAfter != "" {
		t, err = time.Parse(dateFormat, notAfter)
		if err != nil {
			log.Fatalf("expiration date: %v", err)
		}
	} else {
		t = truncateDate(time.Now().Add(defaultAge))
	}

	if ca {
		if _, err := os.Stat(caCert); err == nil {
			log.Fatalf("CA certificate file already exists: %s", caCert)
		}
		if _, err := os.Stat(caKey); err == nil {
			log.Fatalf("CA private key file already exists: %s", caKey)
		}

		if err := createCA(caCert, caKey, t); err != nil {
			log.Fatal(err)
		}
	}

	if client {
		if _, err := os.Stat(cert); err == nil {
			log.Fatalf("Client certificate file already exists: %s", cert)
		}
		if _, err := os.Stat(key); err == nil {
			log.Fatalf("Client private key file already exists: %s", key)
		}

		if err := createClientCert(cert, key, name, caCert, caKey, t); err != nil {
			log.Fatal(err)
		}
	}
}

func createCA(certFile, keyFile string, notAfter time.Time) error {
	pub, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}
	keyData, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().Unix()),
		NotBefore:             truncateDate(time.Now()),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certData, err := x509.CreateCertificate(nil, template, template, pub, key)
	if err != nil {
		return err
	}

	if err := writePEM(certFile, "CERTIFICATE", certData, 0644); err != nil {
		return err
	}

	log.Printf("CA certificate written to file %s", certFile)

	if err := writePEM(keyFile, "PRIVATE KEY", keyData, 0600); err != nil {
		return err
	}

	log.Printf("CA private key written to file %s", keyFile)

	return nil
}

func createClientCert(certFile, keyFile, name, caCertFile, caKeyFile string, notAfter time.Time) error {
	caCertData, err := readPEM(caCertFile)
	if err != nil {
		return err
	}
	caCert, err := x509.ParseCertificate(caCertData)
	if err != nil {
		panic(err)
	}

	caKeyData, err := readPEM(caKeyFile)
	if err != nil {
		return err
	}
	caKey, err := x509.ParsePKCS8PrivateKey(caKeyData)
	if err != nil {
		return err
	}

	pub, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}
	keyData, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().Unix()),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             truncateDate(time.Now()),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	certData, err := x509.CreateCertificate(nil, template, caCert, pub, caKey)
	if err != nil {
		return err
	}

	if err := writePEM(certFile, "CERTIFICATE", certData, 0644); err != nil {
		return err
	}

	log.Printf("Client certificate written to file %s", certFile)

	if err := writePEM(keyFile, "PRIVATE KEY", keyData, 0600); err != nil {
		return err
	}

	log.Printf("Client private key written to file %s", keyFile)

	return nil
}

func writePEM(filename, blockType string, data []byte, perm os.FileMode) error {
	text := pem.EncodeToMemory(&pem.Block{
		Type:  blockType,
		Bytes: data,
	})

	return ioutil.WriteFile(filename, text, perm)
}

func readPEM(filename string) ([]byte, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	b, _ := pem.Decode(data)
	return b.Bytes, nil
}

func truncateDate(t time.Time) time.Time {
	year, month, day := t.Date()
	return time.Date(year, month, day, 0, 0, 0, 0, t.Location())
}

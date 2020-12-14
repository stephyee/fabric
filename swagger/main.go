package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/hyperledger/fabric/internal/pkg/comm"
	swagger "github.com/hyperledger/fabric/swagger/client"
)

func main() {
	var err error
	caCertPool := x509.NewCertPool()
	caFilePEM, err := ioutil.ReadFile("/Users/tiffanyharris/code/go/src/github.com/hyperledger/fabric/demo/config/crypto/ordererOrganizations/example.com/orderers/orderer1.example.com/tls/ca.crt")
	if err != nil {
		log.Fatal(err)
	}
	err = comm.AddPemToCertPool(caFilePEM, caCertPool)
	if err != nil {
		log.Fatal(err)
	}

	tlsClientCert, err := tls.LoadX509KeyPair("/Users/tiffanyharris/code/go/src/github.com/hyperledger/fabric/demo/config/crypto/ordererOrganizations/example.com/orderers/orderer1.example.com/tls/server.crt", "/Users/tiffanyharris/code/go/src/github.com/hyperledger/fabric/demo/config/crypto/ordererOrganizations/example.com/orderers/orderer1.example.com/tls/server.key")
	if err != nil {
		log.Fatal(err)
	}

	cc := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      caCertPool,
				Certificates: []tls.Certificate{tlsClientCert},
			},
		},
	}

	config := &swagger.Configuration{
		BasePath:   "https://127.0.0.1:26504/participation/v1",
		HTTPClient: cc,
	}

	c := swagger.NewAPIClient(config)
	cl, resp, err := c.ChannelsApi.ListChannels(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("CL=%v Resp=%v\n", cl, resp)
}

package main

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/tokopedia/cryptography-example/digital-signature/go-example/lib"
	encryptionLib "github.com/tokopedia/cryptography-example/encryption/go-example/lib"
)

type PaddingType string

type SignedData struct {
	Signature string `json:"signature"`
	Key       string `json:"key"`
	Payload   string `json:"payload"`
}

const (
	JSON_GET_TOKEN    = "get_token.json"
	JSON_HEALTH_CHECK = "health_check.json"
	JSON_GET_OFFER    = "get_offer.json"
	JSON_PAYMENT      = "payment.json"
)

const (
	SELECTED_PAYLOAD = JSON_GET_TOKEN
)

func main() {
	payload, err := readPayload()
	if err != nil {
		log.Fatal(err)
	}

	privKeyStr, err := os.ReadFile("../../key/priv.pem")
	if err != nil {
		log.Fatal(err)
	}

	privKey, err := lib.ParseRsaPrivateKeyFromPemStr(string(privKeyStr))
	if err != nil {
		log.Fatal(err)
	}

	pubKeyStr, err := ioutil.ReadFile("../../key/partner_public_key.pem")
	if err != nil {
		log.Fatal(err)
	}

	pubKey, err := lib.ParseRsaPublicKeyFromPemStr(string(pubKeyStr))
	if err != nil {
		log.Fatal(err)
	}

	signer := lib.SignatureTypePSS{}
	signature, err := signer.Sign(privKey, string(payload))
	if err != nil {
		log.Fatal(err)
	}

	encPayload, encKey, err := encryptionLib.Encrypt(pubKey, payload)
	if err != nil {
		log.Fatal(err)
	}

	var signedData = SignedData{
		Signature: signature,
		Key:       encKey,
		Payload:   string(encPayload),
	}

	prettyJson, _ := json.MarshalIndent(signedData, "", "  ")
	fmt.Printf("%s\n", prettyJson)

	// write to file
	_ = ioutil.WriteFile("result_"+SELECTED_PAYLOAD, prettyJson, 0644)
}

func readPayload() ([]byte, error) {
	file, err := os.Open(SELECTED_PAYLOAD)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	byteValue, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, err
	}

	return byteValue, nil
}

type SignerItf interface {
	Sign(privKey *rsa.PrivateKey, msg string) (string, error)
	Verify(pubKey *rsa.PublicKey, msg, signature string) error
}

func PaddingTypeFactory(PaddingType PaddingType) (SignerItf, error) {
	switch PaddingType {
	case "PKCS":
		return &lib.SignatureTypePKCS{}, nil
	case "PSS":
		return &lib.SignatureTypePSS{}, nil
	default:
		return nil, errors.New("unsupported padding type")
	}
}

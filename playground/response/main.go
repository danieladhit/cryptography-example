package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/tokopedia/cryptography-example/digital-signature/go-example/lib"
	encryptionLib "github.com/tokopedia/cryptography-example/encryption/go-example/lib"
)

type SignedData struct {
	Signature string `json:"signature"`
	Key       string `json:"key"`
	Payload   string `json:"payload"`
}

func main() {
	signedData, err := readConfig()
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

	decPayload, err := encryptionLib.Decrypt(privKey, []byte(signedData.Payload), signedData.Key)
	if err != nil {
		log.Fatal(err)
	}

	pubKeyStr, err := os.ReadFile("../../key/partner_public_key.pem")
	if err != nil {
		log.Fatal(err)
	}

	pubKey, err := lib.ParseRsaPublicKeyFromPemStr(string(pubKeyStr))
	if err != nil {
		log.Fatal(err)
	}

	signer := lib.SignatureTypePSS{}
	signature := signedData.Signature
	stringPayload := string(decPayload)

	err = signer.Verify(pubKey, stringPayload, signature)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("isSignatureVerified: ", err == nil)

	var prettyJson bytes.Buffer
	json.Indent(&prettyJson, decPayload, "", "  ")
	fmt.Printf("%s\n", prettyJson.Bytes())

	// write to file
	_ = ioutil.WriteFile("result.json", prettyJson.Bytes(), 0644)
}

func readConfig() (*SignedData, error) {
	file, err := os.Open("response.json")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	byteValue, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, err
	}

	var signedData SignedData
	err = json.Unmarshal(byteValue, &signedData)
	if err != nil {
		return nil, err
	}

	return &signedData, nil
}

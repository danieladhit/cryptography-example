package main

import (
	"io/ioutil"
	"log"

	"github.com/tokopedia/cryptography-example/encryption/go-example/lib"
)

func main() {
	// Read private key
	privKeyStr, err := ioutil.ReadFile("../../key/priv.pem")
	if err != nil {
		log.Fatal(err)
	}

	// Parse private key
	privKey, err := lib.ParseRsaPrivateKeyFromPemStr(string(privKeyStr))
	if err != nil {
		log.Fatal(err)
	}

	// Read public key
	pubKeyStr, err := ioutil.ReadFile("../../key/pub.pem")
	if err != nil {
		log.Fatal(err)
	}

	// Parse public key
	pubKey, err := lib.ParseRsaPublicKeyFromPemStr(string(pubKeyStr))
	if err != nil {
		log.Fatal(err)
	}

	// Payload
	//payload := `{"name":"john-doe", "method":"hello-world", "value":"lorem-ipsum"}`
	payload := `{"client_id": "tokopedia", "client_secret": "JvOL0Pz9hVbPzfRP5JF6Ipj", "timestamp": "2024-01-30 07:02:00"}`

	// Encryption
	encPayload, encKey, err := lib.Encrypt(pubKey, []byte(payload))
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Encrypted Payload: ", string(encPayload))
	log.Println("Encrypted Key: ", encKey)

	// Decryption
	decPayload, err := lib.Decrypt(privKey, encPayload, encKey)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Decrypted Payload: ", string(decPayload))
}

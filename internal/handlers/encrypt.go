package handlers

import (
	"fmt"
	"net/http"

	"github.com/samdandy/go_crypto/utils"
)

func GenerateKeyPairHandler(w http.ResponseWriter, r *http.Request) {
	privateKey := utils.GeneratePrivateKey()
	privateKeyPEM := privateKey.ToPEM()
	publicKey := privateKey.PublicKey()
	publicKeyPEM := publicKey.ToPEM()
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Write([]byte(privateKeyPEM))
	w.Write([]byte("\n"))
	w.Write([]byte(publicKeyPEM))

}

func EncryptMessageHandler(w http.ResponseWriter, r *http.Request) {
	formValues := map[string]string{}
	missingHeaders := []string{}
	formValues["sender_private_key"] = r.FormValue("sender_private_key")
	formValues["recipient_public_key"] = r.FormValue("recipient_public_key")
	formValues["message"] = r.FormValue("message")
	for k, v := range formValues {
		if v == "" {
			missingHeaders = append(missingHeaders, k)
		}
	}
	if len(missingHeaders) > 0 {
		http.Error(w, fmt.Sprintf("Missing form values: %v", missingHeaders), http.StatusBadRequest)
		return
	}
	publicKey := utils.PublicKeyFromPEM(formValues["recipient_public_key"])
	ciphertext, err := utils.EncryptAndSign([]byte(formValues["message"]), publicKey, utils.PrivateKeyFromPEM(formValues["sender_private_key"]))
	if err != nil {
		http.Error(w, "Encryption failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(fmt.Sprintf("%x", ciphertext)))
}

func DecryptMessageHandler(w http.ResponseWriter, r *http.Request) {
	formValues := map[string]string{}
	missingHeaders := []string{}
	formValues["recipient_private_key"] = r.FormValue("recipient_private_key")
	formValues["sender_public_key"] = r.FormValue("sender_public_key")
	formValues["ciphertext"] = r.FormValue("ciphertext")
	for k, v := range formValues {
		if v == "" {
			missingHeaders = append(missingHeaders, k)
		}
	}
	if len(missingHeaders) > 0 {
		http.Error(w, fmt.Sprintf("Missing form values: %v", missingHeaders), http.StatusBadRequest)
		return
	}
	privateKey := utils.PrivateKeyFromPEM(formValues["recipient_private_key"])
	ciphertext, err := utils.DecodeUserMessageInput(formValues["ciphertext"])
	if err != nil {
		http.Error(w, "Invalid ciphertext", http.StatusInternalServerError)
		return
	}
	senderPublicKey := utils.PublicKeyFromPEM(formValues["sender_public_key"])
	plaintext, err := utils.DecryptAndVerify(ciphertext, privateKey, senderPublicKey)
	if err != nil {
		http.Error(w, "Decryption failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(plaintext))
}

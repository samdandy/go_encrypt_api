package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"io"
	"log"
)

type PrivateKey struct {
	Key *rsa.PrivateKey
}

type PublicKey struct {
	Key *rsa.PublicKey
}

func GeneratePrivateKey() *PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
		return nil
	}
	return &PrivateKey{Key: key}
}

func (p *PrivateKey) ToPEM() string {
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(p.Key)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})
	return string(privateKeyPEM)
}

func (p *PrivateKey) PublicKey() *PublicKey {
	return &PublicKey{Key: &p.Key.PublicKey}
}

func (p *PublicKey) ToPEM() string {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(p.Key)
	if err != nil {
		log.Fatalf("Failed to marshal public key: %v", err)
		return ""
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})
	return string(publicKeyPEM)
}

func (p *PrivateKey) Sign(message []byte) ([]byte, error) {
	hash := sha256.New()
	hash.Write(message)
	hashed := hash.Sum(nil)

	signature, err := rsa.SignPKCS1v15(rand.Reader, p.Key, 0, hashed)
	if err != nil {
		return nil, err
	}
	return signature, nil
}

func (p *PublicKey) Verify(message []byte, signature []byte) error {
	hash := sha256.New()
	hash.Write(message)
	hashed := hash.Sum(nil)

	return rsa.VerifyPKCS1v15(p.Key, 0, hashed, signature)
}

func EncryptMessage(message []byte, recipientPub *PublicKey) ([]byte, error) {
	// Generate random AES key (32 bytes = AES-256)
	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, aesKey); err != nil {
		return nil, err
	}

	// Encrypt the message with AES-GCM
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	encryptedMessage := gcm.Seal(nonce, nonce, message, nil)

	// Encrypt the AES key with recipient's RSA public key
	hash := sha256.New()
	encryptedKey, err := rsa.EncryptOAEP(hash, rand.Reader, recipientPub.Key, aesKey, nil)
	if err != nil {
		return nil, err
	}

	// Combine: [encryptedKeyLength(2 bytes)][encryptedKey][encryptedMessage]
	result := make([]byte, 2+len(encryptedKey)+len(encryptedMessage))
	result[0] = byte(len(encryptedKey) >> 8)
	result[1] = byte(len(encryptedKey))
	copy(result[2:], encryptedKey)
	copy(result[2+len(encryptedKey):], encryptedMessage)

	return result, nil
}

func EncryptAndSign(message []byte, recipientPub *PublicKey, senderPriv *PrivateKey) ([]byte, error) {
	signature, err := senderPriv.Sign(message)
	if err != nil {
		return nil, err
	}

	signedMessage := make([]byte, 2+len(signature)+len(message))
	signedMessage[0] = byte(len(signature) >> 8)
	signedMessage[1] = byte(len(signature))
	copy(signedMessage[2:], signature)
	copy(signedMessage[2+len(signature):], message)
	return EncryptMessage(signedMessage, recipientPub)
}

func DecryptMessage(data []byte, recipientPriv *PrivateKey) ([]byte, error) {
	keyLen := int(data[0])<<8 | int(data[1])

	// Extract encrypted AES key and encrypted message
	encryptedKey := data[2 : 2+keyLen]
	encryptedMessage := data[2+keyLen:]

	// Decrypt the AES key with RSA
	hash := sha256.New()
	aesKey, err := rsa.DecryptOAEP(hash, rand.Reader, recipientPriv.Key, encryptedKey, nil)
	if err != nil {
		return nil, err
	}

	// Decrypt the message with AES-GCM
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	nonce, ciphertext := encryptedMessage[:nonceSize], encryptedMessage[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func DecryptAndVerify(encryptedData []byte, recipientPriv *PrivateKey, senderPub *PublicKey) ([]byte, error) {
	decrypted, err := DecryptMessage(encryptedData, recipientPriv)
	if err != nil {
		return nil, err
	}

	sigLen := int(decrypted[0])<<8 | int(decrypted[1])

	// Extract signature and original message
	signature := decrypted[2 : 2+sigLen]
	message := decrypted[2+sigLen:]

	// Verify the signature
	err = senderPub.Verify(message, signature)
	if err != nil {
		return nil, err
	}

	return message, nil
}

func PrivateKeyFromPEM(pemStr string) *PrivateKey {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil
	}

	if block.Type != "RSA PRIVATE KEY" && block.Type != "PRIVATE KEY" {
		return nil
	}

	var key *rsa.PrivateKey
	var err error
	if block.Type == "RSA PRIVATE KEY" {
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil
		}
	} else {
		parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil
		}
		var ok bool
		key, ok = parsedKey.(*rsa.PrivateKey)
		if !ok {
			return nil
		}
	}

	return &PrivateKey{Key: key}
}

func PublicKeyFromPEM(pemStr string) *PublicKey {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil
	}

	if block.Type != "PUBLIC KEY" && block.Type != "RSA PUBLIC KEY" {
		return nil
	}

	var parsedKey interface{}
	var err error

	if block.Type == "PUBLIC KEY" {
		parsedKey, err = x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil
		}
	} else {
		parsedKey, err = x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil
		}
	}

	key, ok := parsedKey.(*rsa.PublicKey)
	if !ok {
		return nil
	}

	return &PublicKey{Key: key}
}
func DecodeUserMessageInput(s string) ([]byte, error) {
	data := make([]byte, hex.DecodedLen(len(s)))
	_, err := hex.Decode(data, []byte(s))
	if err != nil {
		return nil, err
	}
	return data, nil
}

package utils

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
)

// KeyPEMToPKCS8 converts a PEM-encoded private key to unencrypted PKCS8 format
func KeyPEMToPKCS8(pemData []byte) ([]byte, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM private key")
	}

	keyBytes := block.Bytes

	// Encrypted private keys are not supported
	if isEncryptedPEMBlock(block) {
		return nil, fmt.Errorf("encrypted private keys are not supported; please provide an unencrypted key")
	}

	// Validate the key format and convert to PKCS#8 format
	switch block.Type {
	case "RSA PRIVATE KEY":
		// PKCS#1 format - parse and re-marshal as PKCS#8
		privKey, err := x509.ParsePKCS1PrivateKey(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse RSA private key: %w", err)
		}
		// Convert to PKCS#8 unencrypted format
		keyBytes, err = x509.MarshalPKCS8PrivateKey(privKey)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal RSA key to PKCS#8: %w", err)
		}

	case "EC PRIVATE KEY":
		// SEC1 format - parse and re-marshal as PKCS#8
		privKey, err := x509.ParseECPrivateKey(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse EC private key: %w", err)
		}
		// Convert to PKCS#8 unencrypted format
		keyBytes, err = x509.MarshalPKCS8PrivateKey(privKey)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal EC key to PKCS#8: %w", err)
		}

	case "PRIVATE KEY":
		// Already in PKCS#8 format
		privKey, err := x509.ParsePKCS8PrivateKey(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS#8 private key: %w", err)
		}
		// Validate that it's a supported key type
		switch privKey.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			// Supported types - already in correct format
		default:
			return nil, fmt.Errorf("unsupported private key type")
		}

	default:
		return nil, fmt.Errorf("unsupported private key format: %s (expected RSA PRIVATE KEY, EC PRIVATE KEY, or PRIVATE KEY)", block.Type)
	}

	return keyBytes, nil
}

// isEncryptedPEMBlock checks if a PEM block is encrypted
func isEncryptedPEMBlock(b *pem.Block) bool {
	return b.Headers["Proc-Type"] == "4,ENCRYPTED"
}

// GenerateID creates a unique ID for the resource
func GenerateID(value string) string {
	if value == "" {
		return ""
	}
	hash := sha1.Sum([]byte(strings.TrimSpace(value)))
	return hex.EncodeToString(hash[:])
}

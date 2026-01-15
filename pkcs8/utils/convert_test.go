package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestKeyPEMToPKCS8RSA(t *testing.T) {
	// Generate a test RSA private key
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	// Convert to PKCS#1 PEM format (RSA PRIVATE KEY)
	privKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privKeyBytes,
	})

	// Test KeyPEMToPKCS8
	result, err := KeyPEMToPKCS8(keyPEM)
	if err != nil {
		t.Fatalf("KeyPEMToPKCS8 failed: %v", err)
	}

	if len(result) == 0 {
		t.Fatal("KeyPEMToPKCS8 returned empty result")
	}

	// Should return valid PKCS#8 format
	parsedKey, err := x509.ParsePKCS8PrivateKey(result)
	if err != nil {
		t.Fatalf("Failed to parse PKCS#8 key: %v", err)
	}

	if _, ok := parsedKey.(*rsa.PrivateKey); !ok {
		t.Fatal("Parsed key is not an RSA private key")
	}
}

func TestKeyPEMToPKCS8AlreadyPKCS8(t *testing.T) {
	// Generate a test RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA private key: %v", err)
	}

	// Convert to PKCS#8 PEM format
	privKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("Failed to marshal PKCS#8 private key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privKeyBytes,
	})

	// Test KeyPEMToPKCS8
	result, err := KeyPEMToPKCS8(keyPEM)
	if err != nil {
		t.Fatalf("KeyPEMToPKCS8 failed: %v", err)
	}

	if len(result) == 0 {
		t.Fatal("KeyPEMToPKCS8 returned empty result")
	}

	// Should return valid PKCS#8 format
	parsedKey, err := x509.ParsePKCS8PrivateKey(result)
	if err != nil {
		t.Fatalf("Failed to parse PKCS#8 key: %v", err)
	}

	if _, ok := parsedKey.(*rsa.PrivateKey); !ok {
		t.Fatal("Parsed key is not an RSA private key")
	}
}

func TestKeyPEMToPKCS8InvalidPEM(t *testing.T) {
	// Test with invalid PEM
	invalidPEM := []byte("not a valid pem block")

	_, err := KeyPEMToPKCS8(invalidPEM)
	if err == nil {
		t.Fatal("KeyPEMToPKCS8 should fail with invalid PEM")
	}
}

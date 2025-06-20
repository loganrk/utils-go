package aes

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAESCipher_Encrypt(t *testing.T) {
	// AES-128, AES-192, AES-256 require key lengths of 16, 24, or 32 bytes respectively.
	key := "thisis32bytekeyforaes256crypto!!" // 32-byte key (AES-256)

	// Table-driven test cases for the Encrypt function
	tests := []struct {
		name        string
		plaintext   string
		expectedErr bool
	}{
		{
			name:        "Encrypt valid plaintext - Success",
			plaintext:   "Hello, secure world!",
			expectedErr: false,
		},
		{
			name:        "Encrypt empty plaintext - Success",
			plaintext:   "",
			expectedErr: false,
		},
	}

	// Loop through all test cases
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := New(key)

			// Encrypt test case
			encrypted, err := c.Encrypt(tt.plaintext)
			if tt.expectedErr {
				assert.Error(t, err, "Encrypt should return an error")
			} else {
				assert.NoError(t, err, "Encrypt should not return an error")
				assert.NotEmpty(t, encrypted, "Encrypted string should not be empty")
			}
		})
	}
}

func TestAESCipher_Decrypt(t *testing.T) {
	// AES-128, AES-192, AES-256 require key lengths of 16, 24, or 32 bytes respectively.
	key := "thisis32bytekeyforaes256crypto!!" // 32-byte key (AES-256)

	// Table-driven test cases for the Decrypt function
	tests := []struct {
		name           string
		ciphertext     string
		expectedResult string
		expectedErr    bool
	}{
		{
			name:           "Decrypt valid ciphertext - Success",
			ciphertext:     "mX6G0oqiFJfimEhZooHzA4ysiJXWQKYEQ90Xy+oAM9E4UH4gQUhporccl4c=", // This is a valid base64-encoded ciphertext
			expectedResult: "Hello, secure world!",
			expectedErr:    false,
		},
		{
			name:           "Decrypt with empty ciphertext - Failure",
			ciphertext:     "",
			expectedResult: "",
			expectedErr:    true,
		},
		{
			name:           "Decrypt corrupted ciphertext - Failure",
			ciphertext:     "not-base64%%%$#&",
			expectedResult: "",
			expectedErr:    true,
		},
		{
			name:           "Decrypt with non-base64 string - Failure",
			ciphertext:     "not-base64string",
			expectedResult: "",
			expectedErr:    true,
		},
	}

	// Loop through all test cases
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := New(key)

			// Decrypt test case
			decrypted, err := c.Decrypt(tt.ciphertext)
			if tt.expectedErr {
				assert.Error(t, err, "Decrypt should return an error")
			} else {
				assert.NoError(t, err, "Decrypt should not return an error")
				assert.Equal(t, tt.expectedResult, decrypted, "Decrypted string should match expected result")
			}
		})
	}
}

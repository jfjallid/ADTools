package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"strings"
)

// gppAESKey is the static AES-256 key Microsoft published in MS14-025. Because
// the key is public, any "cpassword" stored by Group Policy Preferences is
// trivially reversible — that is the whole point of the finding.
// (4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b)
var gppAESKey = []byte{
	0x4e, 0x99, 0x06, 0xe8, 0xfc, 0xb6, 0x6c, 0xc9,
	0xfa, 0xf4, 0x93, 0x10, 0x62, 0x0f, 0xfe, 0xe8,
	0xf4, 0x96, 0xe8, 0x06, 0xcc, 0x05, 0x79, 0x90,
	0x20, 0x9b, 0x09, 0xa4, 0x33, 0xb6, 0x6c, 0x1b,
}

// decryptGPPPassword decrypts a GPP cpassword blob (MS14-025) to its plaintext.
// The blob is base64 (with the trailing padding stripped by Windows) over
// AES-256-CBC ciphertext with an all-zero IV; the plaintext is UTF-16LE.
func decryptGPPPassword(cpassword string) (string, error) {
	cpassword = strings.TrimSpace(cpassword)
	if cpassword == "" {
		return "", errors.New("empty cpassword")
	}
	// Windows strips base64 padding; restore it so the decoder accepts the blob.
	if m := len(cpassword) % 4; m != 0 {
		cpassword += strings.Repeat("=", 4-m)
	}
	ct, err := base64.StdEncoding.DecodeString(cpassword)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(gppAESKey)
	if err != nil {
		return "", err
	}
	if len(ct) == 0 || len(ct)%block.BlockSize() != 0 {
		return "", errors.New("ciphertext length is not a multiple of the AES block size")
	}
	iv := make([]byte, block.BlockSize()) // MS14-025 uses an all-zero IV
	plain := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, ct)
	return decodeUTF16Pairs(pkcs7Unpad(plain), false), nil
}

// pkcs7Unpad removes PKCS#7 padding; it returns the input unchanged if the
// padding byte is implausible (defensive, since the key is fixed).
func pkcs7Unpad(b []byte) []byte {
	if len(b) == 0 {
		return b
	}
	pad := int(b[len(b)-1])
	if pad <= 0 || pad > len(b) {
		return b
	}
	return b[:len(b)-pad]
}

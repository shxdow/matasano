package matasano

import (
	"crypto/aes"
	"errors"
	"fmt"
	"log"
)

// PadPKCS7 pads an arbitrary length string to a certain boundary
// specified by size
func PadPKCS7(in []byte, size int) ([]byte, error) {

	if len(in) > size {
		return nil, errors.New(fmt.Sprintf("size %d is lower than input length %d", size, len(in)))
	}

	if len(in) == size {
		return in, nil
	}

	pad := size - len(in)

	for i := 0; i < pad; i++ {
		in = append(in, byte(pad))
	}

	return in, nil
}
func AESEncryptECB(data, key []byte) ([]byte, error) {

	var pad int
	ciphertext := make([]byte, len(data))
	size := len(key)

	blocks, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	pad = (len(data)/blocks.BlockSize() + 1) * blocks.BlockSize()

	if len(data)%blocks.BlockSize() != 0.0 {
		data, err = PadPKCS7(data, pad)
		if err != nil {
			return nil, err
		}
	}

	for i := 0; i < len(ciphertext)-size; i += size {
		blocks.Encrypt(ciphertext[i:i+size], data[i:i+size])
	}

	return ciphertext, nil
}

package matasano

import (
	"crypto/aes"
	"errors"
)

// PadLenPKCS7 returns the length of the padding applied
// by PadPKCS7(). If no padding is detected 0 is returned
func PadLenPKCS7(in []byte, block_size int) (int, error) {

	if len(in)%block_size != 0 {
		return 0, nil
	}

	// Pick the last byte, read its value N and
	// verify that the last N values are all equal
	last := int(in[len(in)-1])

	for i := 0; i < last; i++ {
		if in[len(in)-i-1] != in[len(in)-1] {
			return 0, errors.New("incorrect padding, block may be corrupted")
		}
	}
	return last, nil
}

// PadPKCS7 pads an arbitrary length string to any block size
// from 1 to 255
func PadPKCS7(in []byte, block_size int) []byte {

	if len(in)%block_size == 0 {
		// If no padding is detected, proceed and
		// apply it now
		if l, err := PadLenPKCS7(in, block_size); l == 0 && err != nil {
			// In order to determine unambiguosly whether
			// the last byte of the last plain text block
			// was introduced via padding or not, an extra
			// block is added. This block is made of the
			// byte used for padding
			for i := 0; i < block_size; i++ {
				in = append(in, byte(16))
			}
		}
		return in
	}

	pad := block_size - (len(in) % block_size)

	// Complete the last block
	for i := 0; i < pad; i++ {
		in = append(in, byte(pad))
	}

	return in
}

func AESEncryptECB(data, key []byte) ([]byte, error) {

	var ciphertext []byte
	block_size := 16

	blocks, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	data = PadPKCS7(data, block_size)

	ciphertext = make([]byte, len(data))

	for i := 0; i <= len(ciphertext)-block_size; i += block_size {
		blocks.Encrypt(ciphertext[i:i+block_size], data[i:i+block_size])
	}

	return ciphertext, nil
}

func AESEncryptCBC(in, key, iv []byte) ([]byte, error) {

	var block_size int = 16
	var cipher []byte

	data := PadPKCS7(in, block_size)

	// Xor the first block with the IV
	enc, err := Xor(data[:block_size], iv)
	if err != nil {
		return nil, err
	}

	c, err := AESEncryptECB(enc, key)
	if err != nil {
		return nil, err
	}

	// remove the extra padding block added by ECB
	c = c[:block_size]

	cipher = append(cipher, c...)

	// Loop over all but the first block
	for i := block_size; i <= len(data)-block_size; i += block_size {

		prev := cipher[i-block_size : i]
		block := data[i : i+block_size]

		// Xor the current block against the one previously encrypted
		x, err := Xor(block, prev)
		if err != nil {
			return nil, err
		}

		// Proceed with the core encryption
		b, err := AESEncryptECB(x, key)
		if err != nil {
			return nil, err
		}

		// remove the extra padding block added by ECB
		b = b[:block_size]

		cipher = append(cipher, b...)
	}

	return cipher, nil
}

func AESDecryptCBC(cipher, key, iv []byte) ([]byte, error) {

	var block_size int = 16
	var plain []byte

	b, err := AESDecryptECB(cipher[:block_size], key)
	if err != nil {
		return nil, err
	}

	// Xor the first block with the IV
	p, err := Xor(b, iv)
	if err != nil {
		return nil, err
	}

	plain = append(plain, p...)

	// Loop over all but the first block
	for i := block_size; i <= len(cipher)-block_size; i += block_size {

		prev := cipher[i-block_size : i]
		block := cipher[i : i+block_size]

		// Proceed with the core encryption on the current block
		b, err := AESDecryptECB(block, key)
		if err != nil {
			return nil, err
		}

		// Xor the current block against the previous cipher
		p, err := Xor(b, prev)
		if err != nil {
			return nil, err
		}

		plain = append(plain, p...)
	}

	return plain, nil
}

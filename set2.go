package matasano

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// PadLenPKCS7 returns the length of the padding applied
// by PadPKCS7(). If no padding is detected 0 is returned
func PadLenPKCS7(in []byte, block_size int) (int, error) {

	if len(in)%block_size != 0 {
		return 0, errors.New("block not aligned")
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

// Generates an AES random key
func AESGenerateKey(size int) ([]byte, error) {

	key := make([]byte, size)

	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func AESEncryptionOracle(plain []byte) ([]byte, error, string) {

	block_size := 16
	keySize := 16
	var enc []byte
	var mode string

	rand.Seed(time.Now().UTC().UnixNano())
	pad := 5 + rand.Intn(5)

	key, err := AESGenerateKey(keySize)
	if err != nil {
		return nil, err, ""
	}

	p := make([]byte, pad)
	for i := 0; i < len(p); i++ {
		p[i] = byte(pad)
	}

	// Pad the input with some bytes before and after the plaintext
	plain = append(plain, p...)
	plain = append(p, plain...)

	// use CBC if even, ECB otherwise
	if rand.Int()%2 == 0 {
		mode = "CBC"
		iv, err := AESGenerateKey(block_size)
		if err != nil {
			return nil, err, ""
		}

		enc, err = AESEncryptCBC(plain, key, iv)
		if err != nil {
			return nil, err, ""
		}
	} else {
		mode = "ECB"
		enc, err = AESEncryptECB(plain, key)
		if err != nil {
			return nil, err, ""
		}
	}

	return enc, nil, mode
}

// DetectionOracle pointed at an array of bytes,
// tells whether it was encrypted in ECB or CBC
func AESDetectionOracle(data []byte, l int) (string, error) {

	// If ECB is going on with a repeating plaintext we should 100%
	// find 2 identical blocks. The only catch is that our plaintext
	// gets mixed with some random bytes. Therefore, with a large enough
	// input we should be able to determine the encryption mode

	size := 16
	b := fmt.Sprintf("%x", data)

	// number of repeating blocks expected for ECB
	// the two blocks removed are the ones adjacent to the random bytes
	m := (l / size) - 2

	// dont look for an exact match so that the function can be used
	// in diffrent contexts
	if n := DetectAESECB(b); n >= m {
		return "ECB", nil
	}

	return "CBC", nil
}

// Challenge 12
// This is the same exact function as before, without some stuff:
// it now uses ECB only and it uses a fixed key that is passed
func ECBFixedEncryptionOracle(plain, key []byte) ([]byte, error) {

	var enc []byte

	// Generate padding length
	rand.Seed(time.Now().UTC().UnixNano())
	pad := 5 + rand.Intn(5)

	p := make([]byte, pad)
	for i := 0; i < len(p); i++ {
		p[i] = byte(pad)
	}

	// Pad the input with some bytes before and after the plaintext
	// plain = append(plain, p...)
	// plain = append(p, plain...)

	enc, err := AESEncryptECB(plain, key)
	if err != nil {
		return nil, err
	}

	return enc, nil
}

// Challenge 12
func ECBByteDecryption(secret, fixedKey []byte) ([]byte, error) {

	var str []byte
	var blockSize int = 16
	var decrypted []byte

	// TODO
	// 	the input is indeed correct
	secretText := make([]byte, base64.StdEncoding.DecodedLen(len(secret)))
	_, err := base64.StdEncoding.Decode(secretText, secret)
	if err != nil {
		return nil, err
	}

	// for some reasons, the last block does not get decrypted
	for x := 0; x < len(secretText)/blockSize; x++ {
		// Slide bytes one by one for each block
		for i := 1; i <= blockSize; i++ {
			str = make([]byte, blockSize-i)
			for j := 0; j < len(str); j++ {
				str[j] = byte('A')
			}

			payload := append(str, secretText[x*blockSize:(x+1)*blockSize]...)

			want, err := ECBFixedEncryptionOracle(payload, fixedKey)
			if err != nil {
				return nil, err
			}

			// now comes the bruteforce part:
			// try every possible byte and see which one matches the output
			for k := 0; k < 255; k++ {
				payload[blockSize-1] = byte(k)

				got, err := ECBFixedEncryptionOracle(payload, fixedKey)
				if err != nil {
					return nil, err
				}

				// fmt.Printf("str: %v\nwant: %v\ngot: %v\033[F\033[F", payload[x*blockSize:(x+1)*blockSize], want[x*blockSize:(x+1)*blockSize], got[x*blockSize:(x+1)*blockSize])

				if bytes.Equal(got[:blockSize], want[:blockSize]) {
					decrypted = append(decrypted, byte(k))
				}
			}
		}
		// fmt.Println(x)
	}
	fmt.Printf("%s\n", string(decrypted[:]))

	return decrypted, nil
}

// A cut-and-paste attack is an assault on the integrity of a security system
// in which the attacker substitutes a section of ciphertext (encrypted text)
// with a different section that looks like (but is not the same as) the one
// removed. The substituted section appears to decrypt normally, along with the
// authentic sections, but results in plaintext (unencrypted text) that serves
// a particular purpose for the attacker. Essentially, the attacker cuts one or
// more sections from the ciphertext and reassembles these sections so that the
// decrypted data will result in coherent but invalid information.
func ParseParams(params string) (url.Values, error) {
	v, err := url.ParseQuery(params)
	if err != nil {
		return nil, err
	}
	return v, nil
}

func ProfileFor(email string) (string, error) {
	v := url.Values{}
	// uid := strconv.Itoa(rand.Intn(99))
	uid := 10

	email = strings.Replace(email, "&", "", -1)
	email = strings.Replace(email, "=", "", -1)

	v.Add("email", email)
	v.Add("uid", strconv.Itoa(uid))
	v.Add("role", "user")

	str, err := url.QueryUnescape(v.Encode())
	if err != nil {
		return "", nil
	}
	return str, nil
}

func EncryptCookie(cookie string, key []byte) ([]byte, error) {

	enc, err := AESEncryptECB([]byte(cookie), key)
	if err != nil {
		return nil, err
	}

	return enc, nil
}

func DecryptCookie(enc, key []byte) ([]byte, error) {

	plain, err := AESDecryptECB(enc, key)
	if err != nil {
		return nil, err
	}

	u, err := ParseParams(string(plain))
	if err != nil {
		return nil, err
	}

	user, err := url.QueryUnescape(u.Encode())
	if err != nil {
		return nil, err
	}

	return []byte(user), nil
}

// This function is what an attacker that intercepted
// the encrypted cookie over the network would call
func SetAdminCookie() ([]byte, error) {

	// “Generate a random AES key and use that will be used
	// throughout the attack. Here lies the assumption that
	// the key shared in this communication does not change
	// ie: a key agreed upon with a secure channel obtained
	// from the use of asymmetric cryptography”
	keySize := 16
	blockSize := 16
	key, err := AESGenerateKey(keySize)
	if err != nil {
		return nil, err
	}

	// cipher 1:
	//         block1: email=AAAAAAAAAA
	//         block2: AAAAAAAAAA&role=
	//         block3: user&uid=10
	//
	// create a new cipher made of
	//         b1 + b2 + b5
	// cipher 2:
	//         block4: email=AAAAAAAAAA
	//         block5: admin&role=user
	//                         &uid=10
	payload1 := "AAAAAAAAAAaaaaaaaaaa"

	c1, err := ProfileFor(string(payload1))
	if err != nil {
		return nil, err
	}

	cipherPart1, err := EncryptCookie(c1, key)
	if err != nil {
		return nil, err
	}

	payload2 := "AAAAAAAAAAadmin"

	c2, err := ProfileFor(string(payload2))
	if err != nil {
		return nil, err
	}

	cipherPart2, err := EncryptCookie(c2, key)
	if err != nil {
		return nil, err
	}

	cutpasted := make([]byte, blockSize*4)
	copy(cutpasted[:blockSize*2], cipherPart1[:blockSize*2])
	copy(cutpasted[blockSize*2:blockSize*3], cipherPart2[blockSize:blockSize*2])
	copy(cutpasted[blockSize*3:blockSize*4], cipherPart1[blockSize*2:blockSize*3])

	// In a real world scenario, before knowing the
	// contents of each block, we would have to leverage
	// one byte at a time decryption (problem 12)
	plain, err := DecryptCookie(cutpasted, key)
	if err != nil {
		return nil, err
	}

	return plain, nil
}

// Round to the multiple of a desired unit
func Round(x, unit float64) float64 {
	return math.Round(x/unit) * unit
}

// Challenge 14
// This challenge is not any harder than the previous one: pass 2 identical
// blocks to detect the beginning of the attacker controlled string
func ECBByteDecryptionHard(secret, fixedKey []byte) ([]byte, error) {

	blockSize := 16
	rand.Seed(time.Now().UTC().UnixNano())
	rndLength := rand.Intn(48)

	rndBytes := make([]byte, rndLength)
	rand.Read(rndBytes)

	i, err := skipBadBlocks(rndBytes)
	if err != nil {
		return nil, err
	} else if Round(float64(rndLength), float64(blockSize)) != float64(i*blockSize) {
		// fmt.Println(rndLength)
		// fmt.Printf("rnd bytes enc: %v, skip: %v", Round(float64(rndLength), float64(blockSize)), i*blockSize)
		return nil, errors.New("failed to skip random bytes")
	}

	plain, err := ECBByteDecryption([]byte(secret), fixedKey)
	if err != nil {
		return nil, err
	}
	return plain, nil
}

func skipBadBlocks(rndBytes []byte) (int, error) {

	keySize := 16
	blockSize := 16

	key, err := AESGenerateKey(keySize)
	if err != nil {
		return -1, err
	}

	block := make([]byte, blockSize*3)
	for i := 0; i < len(block); i++ {
		block[i] = byte('A')
	}

	c, err := AESEncryptECB(append(rndBytes, block...), key)
	if err != nil {
		return -1, err
	}

	for i := 0; i < len(c)/blockSize; i++ {
		if bytes.Equal(c[blockSize*i:blockSize*(i+1)], c[blockSize*(i+1):blockSize*(i+2)]) {
			return i, nil
		}
	}
	return 0, nil
}

// Challenge 15
func UnpadPKCS7(str []byte) ([]byte, error) {
	blockSize := 16
	padLen, err := PadLenPKCS7(str, blockSize)
	if err != nil {
		return nil, err

	}
	return str[:padLen], nil
}

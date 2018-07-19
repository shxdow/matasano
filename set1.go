package matasano

import (
	"encoding/base64"
	"encoding/hex"
	"log"
)

/* challenge 1 */
func HexToBase64(s string) string {
	r, err := hex.DecodeString(s)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("%s\n", r)
	return base64.StdEncoding.EncodeToString(r)
}

/* challenge 2 */
func FixedXor(s1, s2 string) string {

	if len(s1) != len(s2) {
		log.Fatal("Different lengths strings\n")
	}

	r := make([]byte, len(s1))
	for i := 0; i < len(s1); i++ {
		r[i] = s1[i] ^ s2[i]
	}

	log.Printf("%s\n", string(r))
	return string(r)
}

/* challenge 2 */

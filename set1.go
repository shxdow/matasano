package matasano

import (
	"encoding/base64"
	"encoding/hex"
	"log"
	"strconv"
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
	bits1, err := strconv.ParseInt(s1, 16, 64)
	if err != nil {
		log.Fatal(err)
	}

	bits2, err := strconv.ParseInt(s2, 16, 64)
	if err != nil {
		log.Fatal(err)
	}

	r := strconv.FormatInt(bits1^bits2, 16)
	log.Printf("%s\n", r)

	return r
}

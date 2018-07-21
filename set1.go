package matasano

import (
	"encoding/base64"
	"encoding/hex"
	"io/ioutil"
	"log"
	"unicode/utf8"
)

/* challenge 1 */
func HexToBase64(s string) string {

	r, err := hex.DecodeString(s)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("set1/c1\t%s\n", r)
	return base64.StdEncoding.EncodeToString(r)
}

/* challenge 2 */
func Xor(s1, s2 []byte) ([]byte, error) {

	if len(s1) != len(s2) {
		log.Fatal("Different lengths buffers\n")
	}

	res := make([]byte, len(s1))
	for i := 0; i < len(s1); i++ {
		res[i] = s1[i] ^ s2[i]
	}

	return res, nil
}

/* challenge 3 */
func SingleByteXor(in []byte, key byte) ([]byte, error) {

	var r []byte = make([]byte, len(in))
	for i := 0; i < len(r); i++ {
		r[i] = in[i] ^ key
	}

	return r, nil
}

/* the computer cant really tell when a word is an english one, so
 * we have to sort of train it to do so by taking real world examples
 * (books will do it) and give him a metric by which it can tell a word from
 * a non word
 */
func AnalyzeCorpus(text string) map[rune]float64 {

	var freq map[rune]float64 = make(map[rune]float64)
	total := utf8.RuneCountInString(text)

	for _, c := range text {
		freq[c] += 1
	}

	/* normalize frequencies */
	for c := range freq {
		freq[c] = freq[c] / float64(total)
	}
	return freq
}

/* Count the frequency of each letter and calculate the score
 * as a weighted sum. naturally, non english words will score lower due to
 * rare characters being more frequent (lower weigth)
 */
func ScoreEnglish(text string, freq map[rune]float64) float64 {

	var score float64
	var t map[rune]float64 = make(map[rune]float64)

	for _, c := range text {
		t[c] += 1
	}

	for c, _ := range t {
		score += t[c] * freq[c]
	}

	return score
}

/* helper function */
func LoadCorpus(filename string) (string, error) {

	text, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatal("Error opening file")
	}
	return string(text), nil
}

package matasano

import (
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
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

	log.Printf("%s", r)
	return base64.StdEncoding.EncodeToString(r)
}

/* challenge 2 */
func Xor(s1, s2 []byte) ([]byte, error) {

	if len(s1) != len(s2) {
		log.Printf("s1: %v, len s1: %d", s1, len(s1))
		log.Printf("s2: %v, len s2: %d", s2, len(s2))
		log.Fatal("Different length buffers\n")
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

// LoadCorpus is a helper function that opens a text file
// and returns its content
func LoadCorpus(filename string) (string, error) {

	text, err := ioutil.ReadFile(filename)
	if err != nil {
		return "", err
	}
	return string(text), nil
}

// initCorpus is a helper function that returns Alice in Wonderland
// and the frequency of english letters, obtained analyzing Alice in Wonderland
func initCorpus() (string, map[rune]float64) {

	data, err := LoadCorpus("_testdata/aliceinwonderland.txt")
	if err != nil {
		log.Fatal(err)
	}

	return data, AnalyzeCorpus(data)
}

// challenge 4
func DetectSingleByteXor(in string, freq map[rune]float64) (byte, string, float64) {
	var key byte
	var plain string
	var best_score float64

	b, err := hex.DecodeString(in)
	if err != nil {
		// bytes may note exist UTF8 (common when dealing with encrypted text)
		b = []byte(in)
		// log.Fatal(err)
	}

	for i := 1; i < 256; i++ {
		enc, err := SingleByteXor(b, byte(i))
		if err != nil {
			log.Fatal(err)
		}
		// log.Printf("%s", enc)
		curr_score := ScoreEnglish(string(enc), freq)
		if curr_score > best_score {
			key = byte(i)
			plain = string(enc)
			best_score = curr_score
		}
	}
	return key, plain, best_score
}

// challenge 5
func RepeatingKeyXor(in, key []byte) []byte {

	var r []byte = make([]byte, len(in))
	l := len(key)

	for i := 0; i < len(in); i++ {
		r[i] = in[i] ^ byte(key[i%l])
	}

	return r
}

// challenge 6
func ComputeHammingDistance(s1, s2 []byte) int {
	var distance int
	mask := byte(01)

	xor, err := Xor(s1, s2)
	if err != nil {
		log.Fatal(err)
	}

	for i := 0; i < len(xor); i++ {
		b := xor[i]
		for j := 0; j < 8; j++ {
			if mask&b != byte(0) {
				distance++
			}
			b = b >> 1
		}
	}
	return distance
}

// Split splits a buffer @buf in N blocks of @size size
func Split(buf []byte, size int) [][]byte {
	var chunk []byte

	chunks := make([][]byte, 0, len(buf)/size+1)
	for len(buf) >= size {
		chunk, buf = buf[:size], buf[size:]
		chunks = append(chunks, chunk)
	}
	if len(buf) > 0 {
		chunks = append(chunks, buf[:len(buf)])
	}
	return chunks
}

// TransposeBlocks will transpose a N x M matrix
func TransposeBlocks(in [][]byte) [][]byte {

	// Create a matrix with N=col and M=1
	transposed_blocks := make([][]byte, len(in[0]))

	for i := 0; i < len(in); i++ {
		for j := 0; j < len(in[i]); j++ {
			// log.Printf("i: %d, j: %d", i, j)
			transposed_blocks[j] = append(transposed_blocks[j], in[i][j])
		}
	}
	return transposed_blocks
}

// BreakRepeatingKeyXor recovers the plain text and the key
// from an encrypted byte array @in
func BreakRepeatingKeyXor(in []byte) ([]byte, string) {
	var key []byte
	var keys []int
	var partial_key []byte
	var plain string
	var plaintext string
	var score float64
	var best_score float64

	// Storing all keys with their respective distances may be interesting...
	distances := make(map[int]float64, 41)

	for i := 2; i < len(in) && i < 41; i++ {
		s := float64(ComputeHammingDistance(in[:i], in[i:i*2]))
		// t := float64(ComputeHammingDistance(in[:i*3], in[i:i*4]))
		// d := (s + t) / (2 * float64(i))
		d := s / float64(i)
		distances[i] = d
	}

	// Extract keysizes and sort them in decreasing order
	for k, _ := range distances {
		keys = append(keys, k)
	}

	// Make the cypher text go through every key
	// and see which one breaks it. The one that does is the one
	// that generates what mostly likely is english
	for _, keysize := range keys {
		partial_key = nil
		plain = ""
		score = 0

		// Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length.
		blocks := Split(in, keysize)

		// Now transpose the blocks: make a block that is the first byte of
		// every block, and a block that is the second byte of every block,
		// and so on.
		tblocks := TransposeBlocks(blocks)
		// tblocks := blocks

		// Compute english's letters frequency
		_, freq := initCorpus()

		// Transposing blocks is only useful for the purpose of solving
		// them with SingleByteXor() but not as much anything else.
		// The plain text is not that interesting either as we would have
		// to transpose the text again...
		// Since this is a symmetric cypher encrypting the input with
		// the know known key will suffice

		// Solve each block as if it was single-byte XOR
		for i := 0; i < len(tblocks); i++ {
			k, p, s := DetectSingleByteXor(string(tblocks[i]), freq)

			partial_key = append(partial_key, k)
			plain += p
			score += s
		}

		// Since multiple keys are being tested, the one that scores the best
		// is the one used for the encryption
		if best_score < score {
			key = partial_key
			plaintext = plain
			best_score = score
		}
	}

	plaintext = string(RepeatingKeyXor(in, key))
	return key, plaintext
}

func AESDecryptECB(data, key []byte) ([]byte, error) {

	plaintext := make([]byte, len(data))
	keySize := len(key)

	if keySize != 8 && keySize != 16 && keySize != 32 {
		return nil, errors.New(fmt.Sprintf("invalid key size, use 8, 16 or 32 bytes (64, 128, 256 bits)"))
	}

	blocks, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	for i := 0; i <= len(plaintext)-blocks.BlockSize(); i += blocks.BlockSize() {
		blocks.Decrypt(plaintext[i:i+blocks.BlockSize()], data[i:i+blocks.BlockSize()])
	}

	return plaintext, nil
}

// challenge 8
func DetectAESECB(in string) int {

	var freq map[string]int = make(map[string]int)
	var max int

	size := 16
	enc := []byte(in)

	// Count frequencies for each block
	for i := 0; i < len(enc)-size; i += size {
		freq[in[i:i+size]] += 1
	}

	// Find the highest number of repeated blocks
	// The higher the number of occurences, the
	// higher the chance it was ECB encrypted
	for _, v := range freq {
		if v > max {
			max = v
		}
	}

	return max
}

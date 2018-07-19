package matasano

import (
	"testing"
)

func TestHexToBase64(t *testing.T) {
	test := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	expected := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

	if r := HexToBase64(test); expected != r {
		t.Failed()
	}
}

func TestFixedXor(t *testing.T) {
	s1 := "1c0111001f010100061a024b53535009181c"
	s2 := "686974207468652062756c6c277320657965"
	expected := "746865206b696420646f6e277420706c6179"

	if r := FixedXor(s1, s2); expected != r {
		t.Failed()
	}
}

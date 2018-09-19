package matasano

import (
	"bytes"
	"testing"
)

func TestPadLenPKCS7(t *testing.T) {
	in := []byte("YELLOW SUBMARINE\x04\x04\x04\x04")
	expected := 4
	block_size := 20

	if got, err := PadLenPKCS7(in, block_size); got != expected && err != nil {
		t.Logf("want: %+v, got: %+v", expected, got)
		t.FailNow()
	}

}

func TestProblem9(t *testing.T) {
	in := []byte("YELLOW SUBMARINE")
	expected := []byte("YELLOW SUBMARINE\x04\x04\x04\x04")
	size := 20

	out := PadPKCS7(in, size)
	l, err := PadLenPKCS7(in, size)
	if err != nil {
		t.Log(err)
		t.FailNow()
	}

	if !bytes.Equal(out[:len(out)-l], expected) {
		t.Logf("%+v", expected)
		t.FailNow()
	} else {
		t.Logf("%+v", out[:len(out)-l])
		t.Logf("%+v", expected)
	}
}

func TestAES(t *testing.T) {

	test := []byte("Hello world")
	key := []byte("YELLOW SUBMARINE")

	// Encrypt the test string
	enc, err := AESEncryptECB(test, key)
	if err != nil {
		t.Log(err)
		t.FailNow()
	}

	// Decrypt the test string
	plain, err := AESDecryptECB(enc, key)
	if err != nil {
		t.Log(err)
		t.FailNow()
	}

	if !bytes.Equal(plain[:len(test)], test) {
		t.Logf("%+v", plain)
		t.Logf("%+v", test)
		t.Logf("p: %s", plain)
		t.Logf("e: %s", test)
		t.FailNow()
	}
}

		t.FailNow()
	}
}

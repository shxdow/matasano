package matasano

import (
	"bytes"
	"testing"
)

func TestProblem9(t *testing.T) {
	in := []byte("YELLOW SUBMARINE")
	expected := []byte("YELLOW SUBMARINE\x04\x04\x04\x04")
	size := 20

	if out, err := PadPKCS7(in, size); !bytes.Equal(out, expected) || err != nil {
		t.Log(err)
		t.FailNow()
	} else {
		t.Logf("%+v", string(out))
		t.Logf("%+v", out)
	}
}

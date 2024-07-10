package probes

import (
	"slices"
	"testing"
)

func Test_decodeProbeData(t *testing.T) {
	bs := `abasdwaeawe\\\a\b\f\n\r\t\v\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\0`
	expected := append([]byte("abasdwaeawe\\\a\b\f\n\r\t\v\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"), 0)
	if !slices.Equal(decodeProbeData(bs), expected) {
		t.Errorf("Expected %q, got %q", expected, decodeProbeData(bs))
	}
}

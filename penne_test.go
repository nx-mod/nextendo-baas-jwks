package main

import (
	"encoding/binary"
	"os"
	"testing"
)

// TestPenneNewsPushBytes builds a news push and writes the framed bytes to penne_push.bin for external
// verification (decoded against the npns parser's expectations). It also checks the frame length is consistent.
func TestPenneNewsPushBytes(t *testing.T) {
	msg := penneNewsPushDefault("nx_news")
	if len(msg) < 4 {
		t.Fatal("too short")
	}
	n := binary.LittleEndian.Uint32(msg)
	if int(n) != len(msg)-4 {
		t.Fatalf("frame length %d != payload %d", n, len(msg)-4)
	}
	if err := os.WriteFile("penne_push.bin", msg, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote penne_push.bin, %d bytes", len(msg))
}

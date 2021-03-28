package main

import (
	"bytes"
	"strconv"
	"strings"
	"testing"
)

func TestRecover_onlyShares(t *testing.T) {
	secrets := []string{
		"1,19943338053965968504353533017903769217",
		"2,161872477868088873785792630750634181303",
		"5,160274174127002500413544256698187925606",
	}

	inBuf := bytes.NewBufferString(strings.Join(secrets, "\n"))

	var (
		outBuf bytes.Buffer
		errBuf bytes.Buffer
	)

	err := cmdRecover(inBuf, &errBuf, &outBuf)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	wantSecret := "7uPIBqGKMPpProBYFFR3S\n"
	if outBuf.String() != wantSecret {
		t.Errorf("unexpected secret. want %q, have %q", wantSecret, outBuf.String())
	}

	if errBuf.Len() != 0 {
		t.Errorf("unexpected diagnostic: %q", errBuf.String())
	}
}

func TestRecover_withGarbage(t *testing.T) {
	secrets := []string{
		"foo",
		"bar",
		"1,19943338053965968504353533017903769217",
		"2,161872477868088873785792630750634181303",
		"",
		"5,160274174127002500413544256698187925606",
		"this is some random junk",
	}

	inBuf := bytes.NewBufferString(strings.Join(secrets, "\n"))

	var (
		outBuf bytes.Buffer
		errBuf bytes.Buffer
	)

	err := cmdRecover(inBuf, &errBuf, &outBuf)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	wantSecret := "7uPIBqGKMPpProBYFFR3S\n"
	if outBuf.String() != wantSecret {
		t.Errorf("unexpected secret. want %q, have %q", wantSecret, outBuf.String())
	}

	expectDiagnostic := "reading share \"foo\": expected two parts\nreading share \"bar\": expected two parts\nreading share \"this is some random junk\": expected two parts\n"
	if expectDiagnostic != errBuf.String() {
		t.Errorf("unexpected diagnostic: %q", errBuf.String())
	}
}

func TestRecover_fromOutput(t *testing.T) {
	secrets := []string{
		"secret: 1tMC82zztRsFLxQAz3ohEG",
		"shares:",
		"1,9039905250649971436987941679095917908",
		"2,149669079771399886069631951128619842789",
		"3,146260035808749368841095381324331189475",
		"4,168953956823167651483065535982114063693",
		"5,47609659354185502263855111386084359716",
	}

	inBuf := bytes.NewBufferString(strings.Join(secrets, "\n"))

	var (
		outBuf bytes.Buffer
		errBuf bytes.Buffer
	)

	err := cmdRecover(inBuf, &errBuf, &outBuf)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	wantSecret := "1tMC82zztRsFLxQAz3ohEG\n"
	if outBuf.String() != wantSecret {
		t.Errorf("unexpected secret. want %q, have %q", wantSecret, outBuf.String())
	}

	if errBuf.Len() != 0 {
		t.Errorf("unexpected diagnostic: %q", errBuf.String())
	}
}

func TestGenerate_invalidParams(t *testing.T) {
	testCases := map[string]struct {
		n         int
		k         int
		expectErr string
	}{
		"unrecoverable": {n: 5, k: 10, expectErr: "will not be enough"},
		"zero N":        {n: 0, k: 0, expectErr: "must be larger than 1"},
		"zero K":        {n: 5, k: 0, expectErr: "must be larger than 1"},
		"negative N":    {n: -1, k: -10, expectErr: "must be larger than 1"},
		"negative K":    {n: 5, k: -10, expectErr: "must be larger than 1"},
	}

	for desc, tc := range testCases {
		t.Run(desc, func(t *testing.T) {
			err := cmdGenerate(tc.n, tc.k, nil)

			if err == nil {
				t.Fatal("expected error, got nil")
			}

			if !strings.Contains(err.Error(), tc.expectErr) {
				t.Errorf("expected error to contain %q, have %s", tc.expectErr, err)
			}
		})
	}
}

func TestGenerate(t *testing.T) {
	var buf bytes.Buffer

	err := cmdGenerate(5, 3, &buf)
	if err != nil {
		t.Fatalf("unexpected error %s", err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")

	if len(lines) != 7 {
		t.Fatalf("want 7 lines, have %d: %q", len(lines), buf.String())
	}

	for idx, line := range lines[2:] {
		wantPrefix := strconv.Itoa(idx+1) + ","
		if !strings.HasPrefix(line, wantPrefix) {
			t.Errorf("unexpected prefix for share %d: want %q, have %q", idx, wantPrefix, line)
		}
	}
}

func TestRoundtrip(t *testing.T) {
	var (
		buf    bytes.Buffer
		errBuf bytes.Buffer
		outBuf bytes.Buffer
	)

	err := cmdGenerate(5, 3, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	lines := strings.SplitN(buf.String(), "\n", 2)
	if len(lines) != 2 {
		t.Fatalf("can't split output into >= 2 lines: %q", buf.String())
	}

	parts := strings.SplitN(lines[0], ": ", 2)
	if len(parts) != 2 {
		t.Fatalf("can't split first line into 2 parts: %q", parts)
	}

	secret := parts[1]
	t.Logf("secret: %q", secret)

	err = cmdRecover(&buf, &errBuf, &outBuf)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	if errBuf.Len() != 0 {
		t.Errorf("unexpected diagnostic output: %q", errBuf.String())
	}

	if outBuf.String() != secret+"\n" {
		t.Errorf("unexpected recovered secret. want %q, have %q", secret, outBuf.String())
	}
}

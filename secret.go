// Command secret is a command line utility that provides (Shamir's Secret Sharing) https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing.
//
// It has three modes of operation:
// - generate a completely new secret and a set of shares
// - recover a secret from a set of shares
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/posener/sharedsecret"
)

func cmdGenerate(n, k int, out io.Writer) error {
	if k > n {
		return errors.New("There will not be enough shares to recover the secret.")
	}

	if n < 1 || k < 1 {
		return errors.New("Number of shares must be larger than 1.")
	}

	shares, secret := sharedsecret.New(int64(n), int64(k))

	fmt.Fprintln(out, "secret:", secret.Text(62))

	fmt.Fprintln(out, "shares:")
	for _, share := range shares {
		fmt.Fprintln(out, share)
	}

	return nil
}

func cmdRecover(in io.Reader, out io.Writer) error {
	scanner := bufio.NewScanner(in)

	var secrets []sharedsecret.Share

	for scanner.Scan() {
		t := scanner.Text()

		if strings.TrimSpace(t) == "" {
			continue
		}

		var s sharedsecret.Share

		err := s.UnmarshalText([]byte(t))
		if err != nil {
			return fmt.Errorf("reading share %q: %w", t, err)
		}

		secrets = append(secrets, s)
	}

	secret := sharedsecret.Recover(secrets...)

	fmt.Fprintln(out, secret.Text(62))

	return nil
}

func die(err error, printUsage bool) {
	fmt.Fprintln(os.Stderr, err.Error())

	if printUsage {
		fmt.Fprintf(os.Stderr, "\nUsage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}

	os.Exit(1)
}

func main() {
	mode := flag.String("mode", "generate", "Mode of operation. One of [generate, recover]")
	minShares := flag.Int("k", 3, "Minimum number of shares required. Must be <= n.")
	numShares := flag.Int("n", 5, "How many shares to generate")
	secrets := flag.String("secrets", "-", "File to read secrets from. Use - to read from stdin.")

	flag.Parse()

	var err error

	switch *mode {
	case "generate":
		err = cmdGenerate(*numShares, *minShares, os.Stdout)
	case "recover":
		var (
			fh  io.ReadCloser
			err error
		)

		switch *secrets {
		case "-":
			fh = os.Stdin
		default:
			fh, err = os.Open(*secrets)
			if err != nil {
				die(err, false)
			}
			defer fh.Close()
		}

		err = cmdRecover(fh, os.Stdout)
	default:
		err = fmt.Errorf("invalid mode %q", *mode)
	}

	if err != nil {
		die(err, true)
	}
}

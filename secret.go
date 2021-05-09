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
	"math"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/posener/sharedsecret"
)

const minShares = 10000 // Minimum number of shares to generate.

func cmdGenerate(n, k int, out io.Writer) error {
	if k > n {
		return errors.New("There will not be enough shares to recover the secret.")
	}

	if n < 1 || k < 1 {
		return errors.New("Number of shares must be larger than 1.")
	}

	// Generate a lot more shares than we need and select random n from them to make recovering the number of shares
	// unfeasible.
	genSecrets := int64(math.Pow(float64(n), 2))
	if genSecrets < minShares {
		genSecrets = minShares
	}

	shares, secret := sharedsecret.New(genSecrets, int64(k))

	rand.Seed(time.Now().UnixNano())
	// Randomize list of shares, get the first n
	rand.Shuffle(len(shares), func(i, j int) {
		shares[i], shares[j] = shares[j], shares[i]
	})

	shares = shares[:n]

	fmt.Fprintln(out, "secret:", secret.Text(62))

	fmt.Fprintf(out, "shares (need at least %d of these for recovery):\n", k)
	for _, share := range shares {
		fmt.Fprintln(out, share)
	}

	return nil
}

func cmdRecover(in io.Reader, diag io.Writer, out io.Writer) error {
	scanner := bufio.NewScanner(in)

	var secrets []sharedsecret.Share

	for scanner.Scan() {
		t := strings.TrimSpace(scanner.Text())

		if t == "" || strings.HasPrefix(t, "secret: ") || strings.HasPrefix(t, "shares") {
			continue
		}

		var s sharedsecret.Share

		err := s.UnmarshalText([]byte(t))
		if err != nil {
			fmt.Fprintf(diag, "reading share %q: %s\n", t, err)
			continue
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

		err = cmdRecover(fh, os.Stderr, os.Stdout)
	default:
		err = fmt.Errorf("invalid mode %q", *mode)
	}

	if err != nil {
		die(err, true)
	}
}

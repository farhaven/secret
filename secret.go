// Command secret is a command line utility that provides (Shamir's Secret Sharing) https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing.
//
// It has three modes of operation:
// - generate a completely new secret and a set of shares
// - generate a set of shares from an existing secret
// - recover a secret from a set of shares
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/posener/sharedsecret"
)

func main() {
	mode := flag.String("mode", "generate", "Mode of operation. One of [generate, recover]")
	minShares := flag.Int("k", 3, "Minimum number of shares required")
	numShares := flag.Int("n", 5, "How many shares to generate")

	flag.Parse()

	switch *mode {
	case "generate", "recover":
	default:
		fmt.Fprintln(os.Stderr, "Invalid mode", *mode)
		flag.PrintDefaults()
		os.Exit(1)
	}

	shares, secret := sharedsecret.New(int64(*numShares), int64(*minShares))

	fmt.Println("secret:", secret.Text(62))

	fmt.Println("shares:")
	for _, share := range shares {
		fmt.Println(share)
	}
}

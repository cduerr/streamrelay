package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func main() {
	identity := flag.String("identity", "1", "identity value (user ID)")
	claim := flag.String("claim", "sub", "JWT claim name for identity")
	secret := flag.String("secret", "", "JWT signing secret (required)")
	expiry := flag.Duration("expires", 24*time.Hour, "token expiry duration (e.g., 24h, 7d)")
	flag.Parse()

	if *secret == "" {
		// Check environment variable.
		*secret = os.Getenv("STREAMRELAY_AUTH_JWT_SECRET")
		if *secret == "" {
			fmt.Fprintln(os.Stderr, "error: --secret is required (or set STREAMRELAY_AUTH_JWT_SECRET)")
			os.Exit(1)
		}
	}

	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		*claim: *identity,
		"iat":  now.Unix(),
		"exp":  now.Add(*expiry).Unix(),
	})

	signed, err := token.SignedString([]byte(*secret))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error signing token: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(signed)
}

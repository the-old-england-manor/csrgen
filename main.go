package main

import (
	"os"

	"github.com/the-old-england-manor/csrgen/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}

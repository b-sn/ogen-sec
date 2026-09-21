// Command securitygen generates implementations of ogen's SecurityHandler interface.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/b-sn/ogen-sec/securitygen"
)

func main() {
	if err := securitygen.Run(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, "securitygen:", err)
		os.Exit(1)
	}
}

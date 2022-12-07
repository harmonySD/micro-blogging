package main

import (
	"bufio"
	"fmt"
	"os"
)

// Calling main
func main() {

	scanner := bufio.NewScanner(os.Stdin)

	if scanner.Scan() {
		line := scanner.Text()

		fmt.Printf("%s\n", line)
	}
}

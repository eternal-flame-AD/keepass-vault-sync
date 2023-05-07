package util

import (
	"os"

	"golang.org/x/term"
)

func AskPass(prompt string) ([]byte, error) {
	termFd := os.Stdin.Fd()
	if _, err := os.Stdout.WriteString(prompt); err != nil {
		return nil, err
	}
	pass, err := term.ReadPassword(int(termFd))
	if err != nil {
		return nil, err
	}
	if _, err := os.Stdout.WriteString("\n"); err != nil {
		return nil, err
	}
	return pass, nil
}

package util

import "strings"

func VaultPathEscape(path string) string {
	path = strings.ReplaceAll(path, "/", "-")
	path = strings.ReplaceAll(path, " ", "_")

	return path
}

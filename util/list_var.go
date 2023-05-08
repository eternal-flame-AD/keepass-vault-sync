package util

import "strings"

type ListVar []string

func (l *ListVar) String() string {
	return strings.Join(*l, ",")
}

func (l *ListVar) Set(value string) error {
	*l = append(*l, value)
	return nil
}

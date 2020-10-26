package auth

import "testing"

const adminAccount Account = Account{
	User:      "admin",
	Readable:  []string{},
	Writeable: []string{},
	Hash:      "$2y$12$G26gni9PVX2lprOyvE44mOnvvM5kLOdGY9oAsC4XdJNQWbZDsMd7K",
}

func TestGetName(t *testing.T) {

}

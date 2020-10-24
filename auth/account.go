package auth

import (
	"path"

	"golang.org/x/crypto/bcrypt"
)

// Account stores the permissions of a user. Can be retrieved from Authdb.getAccount or Authdb.getDefault
type Account struct {
	User      string
	Readable  []string
	Writeable []string
	Hash      string
}

// GetName returns the name of the Account
func (account Account) GetName() string {
	return account.User
}

// CanRead returns true if the Account can read the queried path
func (account Account) CanRead(queriedpath string) bool {
	for ok := true; ok; ok = (queriedpath != "." && queriedpath != "/") {
		for _, readablepath := range account.Readable {
			if match, _ := path.Match(readablepath, queriedpath); match {
				return true
			}
		}
		queriedpath = path.Dir(queriedpath)
	}

	return false
}

// CanWrite returns true if the Account can write the queried path
func (account Account) CanWrite(queriedpath string) bool {
	for ok := true; ok; ok = (queriedpath != "." && queriedpath != "/") {
		for _, writeablepath := range account.Writeable {
			if match, _ := path.Match(writeablepath, queriedpath); match {
				return true
			}
		}
		queriedpath = path.Dir(queriedpath)
	}

	return false
}

// CheckPassword checks a password against the Account
func (account Account) CheckPassword(password []byte) bool {
	if account.Hash == "" {
		return true
	}
	return bcrypt.CompareHashAndPassword([]byte(account.Hash), password) == nil
}

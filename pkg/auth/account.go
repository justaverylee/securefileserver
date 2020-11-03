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

func canAccess(acl []string, qpath string) bool {
	for {
		for _, readablepath := range acl {
			if match, _ := path.Match(readablepath, qpath); match {
				return true
			}
		}

		nextpath := path.Dir(qpath)
		if nextpath == qpath {
			return false
		}
		qpath = nextpath
	}
}

// CanRead returns true if the Account can read the queried path
func (account Account) CanRead(queriedpath string) bool {
	return canAccess(account.Readable, queriedpath)
}

// CanWrite returns true if the Account can write the queried path
func (account Account) CanWrite(queriedpath string) bool {
	return canAccess(account.Writeable, queriedpath)
}

// CheckPassword checks a password against the Account
func (account Account) CheckPassword(password []byte) bool {
	if account.Hash == "" {
		return true
	}
	return bcrypt.CompareHashAndPassword([]byte(account.Hash), password) == nil
}

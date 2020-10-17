package auth

import "errors"

// store can be any key value store. It is what we use as the backing for our
type store interface {
	Get(k string) (*Account, bool)
	Set(user string, x *Account)
	Delete(user string)

	Save() error
}

// Auth interface can be implemented to store authentication in a way
type Auth struct {
	store          store
	defaultAccount Account
}

// MakeAuth creates an auth from an underlying store
func MakeAuth(store store, defaultAccount Account) *Auth {
	return &Auth{
		store:          store,
		defaultAccount: defaultAccount,
	}
}

// MakeAuthFromStore creates an auth from an underlying store, with nil defaultAccount
func MakeAuthFromStore(store store) *Auth {
	return MakeAuth(store, Account{})
}

// SetDefault updates the default account
func (auth Auth) SetDefault(account Account) {
	auth.defaultAccount = account
}

// GetDefault returns the default account
func (auth Auth) GetDefault() *Account {
	return &auth.defaultAccount
}

// GetAccount gets an account if the username and password match
func (auth Auth) GetAccount(username string, password []byte) (*Account, error) {
	toCheck, exists := auth.store.Get(username)
	if exists {
		if toCheck.CheckPassword(password) {
			return toCheck, nil
		}
	}
	return nil, errors.New("Failed to Authenticate")
}

// ViewAccount allows viewing or editing an account. This does not provide security
func (auth Auth) ViewAccount(username string) (*Account, bool) {
	return auth.store.Get(username)
}

// AddUser adds a user to the store, and writes the store back
func (auth Auth) AddUser(acc *Account) {
	auth.store.Set(acc.User, acc)
	auth.store.Save()
}

// DeleteUser removes a user from the store and writes the store back
func (auth Auth) DeleteUser(username string) {
	auth.store.Delete(username)
	auth.store.Save()
}

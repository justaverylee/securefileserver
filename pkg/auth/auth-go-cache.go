package auth

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/patrickmn/go-cache"
)

// GoCacheStore implements the Authdb interface with an in memory auth database that is backed by a file on disk
type GoCacheStore struct {
	filename string
	watcher  *fsnotify.Watcher
	cache    *cache.Cache
}

// MakeEmptyGoCacheStore creates an empty in memory store which is not backed to disk, but can be saved to disk
func MakeEmptyGoCacheStore(filename string) *GoCacheStore {
	store := GoCacheStore{
		filename: filename,
		watcher:  nil,
		cache:    cache.New(cache.NoExpiration, 0*time.Second),
	}

	return &store
}

// MakeGoCacheStore create a new in memory store loaded from the filename passed
func MakeGoCacheStore(filename string) (*GoCacheStore, error) {
	watch, newwatcherr := fsnotify.NewWatcher()
	if newwatcherr != nil {
		return nil, newwatcherr
	}

	addwatcherr := watch.Add(filename)
	if addwatcherr != nil {
		return nil, addwatcherr
	}

	store := GoCacheStore{
		filename: filename,
		watcher:  watch,
		cache:    cache.New(cache.NoExpiration, 0*time.Second),
	}

	loaderr := reload(filename, &store)
	if loaderr != nil {
		return nil, loaderr
	}

	go waitForUpdates(watch, &store)

	return &store, nil
}

// Get gets from the store
func (store GoCacheStore) Get(k string) (Account, bool) {
	account, found := store.cache.Get(k)
	if found {
		return account.(Account), found
	}
	return Account{}, found
}

// Set sets to the store
func (store GoCacheStore) Set(k string, x Account) {
	store.cache.SetDefault(k, x)
}

// Delete deletes a key
func (store GoCacheStore) Delete(k string) {
	store.cache.Delete(k)
}

// GetAll returns the database as a map from key to values
func (store GoCacheStore) GetAll() map[string]Account {
	accounts := make(map[string]Account, store.cache.ItemCount())

	items := store.cache.Items()

	for k, v := range items {
		accounts[k] = v.Object.(Account)
	}
	return accounts
}

// Save writes to disk
func (store GoCacheStore) Save() error {
	items := store.cache.Items()

	var accounts []Account

	for _, v := range items {
		accounts = append(accounts, v.Object.(Account))
	}

	data, jsonerr := json.Marshal(accounts)
	if jsonerr != nil {
		return jsonerr
	}

	return ioutil.WriteFile(store.filename, data, 0644)
}

func reload(filename string, store *GoCacheStore) error {
	data, fileerr := ioutil.ReadFile(filename)
	if fileerr != nil {
		return fileerr
	}

	var readdata []Account

	jsonerr := json.Unmarshal(data, &readdata)
	if jsonerr != nil {
		return jsonerr
	}

	items := make(map[string]cache.Item)

	for _, acc := range readdata {
		items[acc.User] = cache.Item{
			Object:     acc,
			Expiration: 0,
		}
	}

	store.cache = cache.NewFrom(cache.NoExpiration, 0*time.Second, items)
	return nil
}

func waitForUpdates(watch *fsnotify.Watcher, store *GoCacheStore) {
	for {
		select {
		case e := <-watch.Events:
			if e.Op != fsnotify.Chmod {
				err := reload(e.Name, store)
				if err != nil {
					fmt.Println("Error reloading auth (see below error message)")
					fmt.Println(err)
				} else {
					fmt.Println("Auth file has been updated.")
				}
			}
		case e := <-watch.Errors:
			fmt.Println("File watch detected an error, auth may not stay up to date with file! Consider restarting the application")
			fmt.Println(e)
		}
	}
}

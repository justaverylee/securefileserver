package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/zggz/securefileserver/auth"
	"golang.org/x/crypto/bcrypt"
)

func contains(slice []string, val string) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}

func remove(slice []string, val string) []string {
	for i, item := range slice {
		if item == val {
			slice[i] = slice[len(slice)-1]
			slice[len(slice)-1] = ""
			return slice[:len(slice)-1]
		}
	}
	return slice
}

func main() {
	authfile := flag.String("auth", "", "(Required) Location to find (or create) the Auth configuration file")
	new := flag.Bool("new", false, "Pass this flag to create an empty auth first rather than loading from disk")

	add := flag.Bool("add", false, "Creates an account with a username, password and permissions")
	edit := flag.Bool("edit", false, "Finds a username, and edits the read and write permissions as well as the password if passed")
	check := flag.Bool("check", false, "Checks a username and password against the auth file. Does not edit.")

	username := flag.String("username", "", "To add a user, pass the username here along with the password. Also use these to check for accounts")
	password := flag.String("password", "", "To add/check a user, pass the password here (Required if username)")

	addread := flag.String("add-read", "", "If creating to or editing an account, enable reading for the account at this path")
	addwrite := flag.String("add-write", "", "If creating to or editing an auth file, enable writing for the account at this path")
	delread := flag.String("del-read", "", "If creating to or editing an auth file, disable reading for the account at this path (only for edit)")
	delwrite := flag.String("del-write", "", "If creating to or editing an auth file, disable writing for the account at this path (only for edit)")

	flag.Parse()

	if *authfile == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	var store *auth.GoCacheStore
	var err error
	if *new {
		fmt.Println("Creating empty store")
		store = auth.MakeEmptyGoCacheStore(*authfile)
	} else {
		fmt.Println("Creating store from file " + *authfile)
		store, err = auth.MakeGoCacheStore(*authfile)
	}

	if err != nil {
		fmt.Print("Recieved error loading the auth configuration file: ")
		fmt.Println(err)
		os.Exit(1)
	}

	authdb := auth.MakeAuthFromStore(store)

	fmt.Println("Successfully loaded/created auth")

	if *add && *username != "" && *password != "" {
		hashedpass, hasherr := bcrypt.GenerateFromPassword([]byte(*password), bcrypt.DefaultCost)

		if hasherr != nil {
			fmt.Print("Recieved error while hashing the password: ")
			fmt.Println(err)
			os.Exit(1)
		}

		fmt.Println("Creating account with username " + *username)

		newAcc := auth.Account{
			User:      *username,
			Readable:  []string{},
			Writeable: []string{},
			Hash:      string(hashedpass),
		}
		if *addread != "" {
			fmt.Println("Account has access to read path " + *addread)
			newAcc.Readable = append(newAcc.Readable, *addread)
		}
		if *addwrite != "" {
			fmt.Println("Account has access to write path " + *addwrite)
			newAcc.Writeable = append(newAcc.Writeable, *addwrite)
		}
		authdb.AddUser(&newAcc)
	} else if *add && (*username == "" || *password == "") {
		fmt.Println("Did not add user because no username or password was passed")
	}

	if *check {
		var acc *auth.Account
		if *password != "" {
			fmt.Println("Checking for username " + *username + " and passed password")
			var fetcherr error
			acc, fetcherr = authdb.GetAccount(*username, []byte(*password))
			if fetcherr != nil {
				fmt.Print("Error getting account: ")
				fmt.Println(fetcherr)
				os.Exit(1)
			}
		} else {
			fmt.Println("Viewing user " + *username)
			var found bool
			acc, found = authdb.ViewAccount(*username)
			if !found {
				fmt.Println("Account not found")
				os.Exit(1)
			}
		}

		fmt.Println("Found account with " + acc.User)
		fmt.Println("Account has access to read paths " + strings.Join(acc.Readable, ", "))
		fmt.Println("Account has access to write paths " + strings.Join(acc.Writeable, ", "))
	}

	if *edit {
		fmt.Println("Editing user " + *username)
		acc, found := authdb.ViewAccount(*username)
		if !found {
			fmt.Println("User did not exist")
		} else {
			if *password != "" {
				fmt.Println("Changing account password")
				hashedpass, hasherr := bcrypt.GenerateFromPassword([]byte(*password), bcrypt.DefaultCost)
				if hasherr != nil {
					fmt.Print("Recieved error while hashing the password: ")
					fmt.Println(err)
					os.Exit(1)
				}
				acc.Hash = string(hashedpass)
			}

			if *addread != "" && !contains(acc.Readable, *addread) {
				fmt.Println("Adding read access to " + *addread)
				acc.Readable = append(acc.Readable, *addread)
			}

			if *addwrite != "" && !contains(acc.Writeable, *addwrite) {
				fmt.Println("Adding write access to " + *addwrite)
				acc.Writeable = append(acc.Writeable, *addwrite)
			}

			if *delread != "" && contains(acc.Readable, *delread) {
				fmt.Println("Removing read access to " + *delread)
				acc.Readable = remove(acc.Readable, *delread)
			}

			if *delwrite != "" && contains(acc.Writeable, *delwrite) {
				fmt.Println("Removing write access to " + *delwrite)
				acc.Writeable = remove(acc.Writeable, *delwrite)
			}

			authdb.AddUser(acc)
		}
	}
}

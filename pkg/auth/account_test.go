package auth

import (
	"testing"
)

var admin Account = Account{
	User:      "admin",
	Readable:  []string{},
	Writeable: []string{},
	Hash:      "$2y$12$G26gni9PVX2lprOyvE44mOnvvM5kLOdGY9oAsC4XdJNQWbZDsMd7K",
}

var def Account = Account{}

var authorized Account = Account{
	User:      "nick",
	Readable:  []string{"/foo"},
	Writeable: []string{},
	Hash:      string("$2y$12$md1lRePghQ.oawY0RXtfvuQjQ4ejPQxZekGmy6Gki/LAs4sylHwHq"), //"password"
}

var badguy Account = Account{
	User:      "zach",
	Readable:  []string{},
	Writeable: []string{},
	Hash:      string("$2y$04$kBNVYvqcAHhkeyLuLgkAueNMV8QFOq92rEk338dkThjGmFCbm47zm "), //"admin"
}

func TestGetName(t *testing.T) {
	got := admin.GetName()
	if got != "admin" {
		t.Errorf("%v; want \"admin\"", got)
	}
}

func CheckPassword(t *testing.T) {
	got := admin.CheckPassword([]byte("admin"))
	if !got {
		t.Errorf("password check failed")
	}
}

// change this to test the helper function
func TestCanAccess(t *testing.T) {
	var tests = []struct {
		description string
		acl         []string
		path        string
		expected    bool
	}{
		//array
		{"allows subdirectory", []string{"/foo", "/bar/baz"}, "/foo/yarr/pop", true},
		{"allows self", []string{"/foo", "/bar/baz"}, "/bar/baz", true},
		{"blocks unrelated", []string{"/foo", "/bar/baz"}, "gibberish", false},
		{"blocks root", []string{"/foo", "/bar/baz"}, "/", false},
		{"root permission allows root", []string{"/"}, "/", true},
		{"root permission allows root file", []string{"/"}, "/bar", true},
		{"root permission allows subdirectory", []string{"/"}, "/bar/baz", true},
		{"empty permission blocks root", []string{}, "/", false},
		{"empty permission blocks root file", []string{}, "/bar", false},
		{"empty permission blocks subdirectories", []string{}, "/bar/baz", false},
		{"wildcard dirname allows", []string{"/bar/baz", "/users/*/data"}, "/users/cat/data", true},
		{"wildcard dirname allows subdirectories", []string{"/bar/baz", "/users/*/data"}, "/users/cat/data/dag/dom", true},
	}

	for _, tt := range tests {
		testname := tt.description
		t.Run(testname, func(t *testing.T) {
			if canAccess(tt.acl, tt.path) != tt.expected {
				if tt.expected {
					t.Errorf("false positive")
				} else {
					t.Errorf("false negative")
				}
			}
		})
	}

	return
}

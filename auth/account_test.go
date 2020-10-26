package auth

import (
	"testing"
	"fmt"
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

// change this to test the helper function
func TestCanRead(t *testing.T) {
	tester1 := Account{
		User:      "test1",
		Readable:  []string{"/foo", "/bar/baz"},
		Writeable: []string{},
		Hash:      "",
	}
	
	var tests = []struct{
		acc Account
		path string
		expected bool
	}{
		//array
		{tester1, "/foo/yarr/pop", true},
		{tester1, "/bar/baz/", true},
		{tester1, "gibberish", false},
		{tester1, "/", false},
	}

    for _, tt := range tests {
        testname := fmt.Sprintf("%v:%v", tt.acc.GetName(), tt.path)
        t.Run(testname, func(t *testing.T) {
            if tt.acc.CanRead(tt.path) != tt.expected {
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

func TestCanWrite(t *testing.T) {

}

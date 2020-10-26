package auth

import "testing"

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

func TestCanRead(t *testing.T) {
	tester := Account{
		User:      "",
		Readable:  []string{"/foo", "/bar/baz"},
		Writeable: []string{},
		Hash:      "",
	}

	positiveTests := []string{"/foo/yarr/pop", "/bar/baz/"}
	negativeTests := []string{"gibberish", "/"}

	for _, s := range positiveTests {
		if !tester.CanRead(s) {
   	    	t.Errorf("Can't read %v\n", s)
		}
	}

	for _, s := range negativeTests {
		if tester.CanRead(s) {
   	    	t.Errorf("Can read %v\n", s)
		}
	}
}

func TestCanWrite(t *testing.T) {

}
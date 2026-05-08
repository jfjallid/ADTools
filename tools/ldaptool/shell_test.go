package main

import (
	"reflect"
	"testing"
)

func TestLastAttrsToken(t *testing.T) {
	cases := []struct {
		before    string
		wantLead  string
		wantAttr  string
		wantOK    bool
	}{
		{"search -attrs cn,sa", "search -attrs cn,", "sa", true},
		{"search -attrs ", "search -attrs ", "", true},
		{"search --attrs ob", "search --attrs ", "ob", true},
		{"search -attrs cn,sn ", "", "", false}, // value ended (trailing space)
		{"search -filter foo", "", "", false},
	}
	for _, c := range cases {
		lead, attr, ok := lastAttrsToken(c.before)
		if ok != c.wantOK || lead != c.wantLead || attr != c.wantAttr {
			t.Errorf("lastAttrsToken(%q) = (%q, %q, %v); want (%q, %q, %v)",
				c.before, lead, attr, ok, c.wantLead, c.wantAttr, c.wantOK)
		}
	}
}

func TestParseArgs(t *testing.T) {
	cases := []struct {
		in      string
		want    []string
		wantErr bool
	}{
		{"", nil, false},
		{"   ", nil, false},
		{"foo", []string{"foo"}, false},
		{"foo bar", []string{"foo", "bar"}, false},
		{"  foo   bar  ", []string{"foo", "bar"}, false},
		{`"hello world"`, []string{"hello world"}, false},
		{`'hello world'`, []string{"hello world"}, false},
		{`foo"bar baz"`, []string{"foobar baz"}, false},
		{`foo "bar baz" qux`, []string{"foo", "bar baz", "qux"}, false},
		{`'it''s'`, []string{"its"}, false}, // adjacent quotes concatenate within token
		{`a\ b`, []string{"a b"}, false},
		{`a\\b`, []string{`a\b`}, false},
		{`"a\"b"`, []string{`a"b`}, false},
		{`"CN=Foo\,Bar"`, []string{`CN=Foo,Bar`}, false},
		{`'a\nb'`, []string{`a\nb`}, false}, // escapes literal inside single quotes
		{`"tab\there"`, []string{"tab\there"}, false},
		{`""`, []string{""}, false}, // explicit empty token
		{`"unterminated`, nil, true},
		{`'unterminated`, nil, true},
		{`trailing\`, nil, true},
	}
	for _, c := range cases {
		got, err := parseArgs(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("parseArgs(%q): expected error, got %v", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseArgs(%q): unexpected error: %v", c.in, err)
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("parseArgs(%q): got %q, want %q", c.in, got, c.want)
		}
	}
}

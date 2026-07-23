package hst

import (
	"reflect"
	"testing"
)

func TestParseLinuxList(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []int
	}{
		{name: "single", input: "0", expected: []int{0}},
		{name: "range", input: "0-2", expected: []int{0, 1, 2}},
		{name: "non-contiguous", input: "0,2-3", expected: []int{0, 2, 3}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual, err := parseLinuxList(test.input)
			if err != nil {
				t.Fatalf("parseLinuxList(%q) returned an error: %v", test.input, err)
			}
			if !reflect.DeepEqual(actual, test.expected) {
				t.Fatalf("parseLinuxList(%q) = %v, expected %v", test.input, actual, test.expected)
			}
		})
	}
}

func TestParseLinuxListRejectsInvalidInput(t *testing.T) {
	for _, input := range []string{"", "1-", "2-1", "a", "0,,1"} {
		t.Run(input, func(t *testing.T) {
			if _, err := parseLinuxList(input); err == nil {
				t.Fatalf("parseLinuxList(%q) unexpectedly succeeded", input)
			}
		})
	}
}

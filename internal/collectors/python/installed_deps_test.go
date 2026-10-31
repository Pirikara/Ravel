package python

import (
	"reflect"
	"testing"
)

func TestParseEggRequirements(t *testing.T) {
	data := []byte("# ignored\nidna==3.10\n[security]\ncryptography>=44\n[:python_version < '3.13']\ntyping-extensions; os_name == 'posix'\n[broken\nignored==1\n[]\nrequests==2.32\n")
	got, invalid := parseEggRequirements(data)
	want := []eggRequirementLine{
		{value: "idna==3.10", line: 2},
		{value: `cryptography>=44; extra == "security"`, line: 4},
		{value: "typing-extensions; (os_name == 'posix') and (python_version < '3.13')", line: 6},
		{value: "requests==2.32", line: 10},
	}
	if !reflect.DeepEqual(got, want) || !reflect.DeepEqual(invalid, []int{7, 8}) {
		t.Fatalf("egg-info requirements parsed incorrectly: got=%#v invalid=%#v", got, invalid)
	}
	for _, line := range got {
		if _, ok := parseInstalledRequirement(line.value); !ok {
			t.Errorf("converted requirement cannot be parsed: %#v", line)
		}
	}
}

func TestParseEggRequirementsInvalidEncoding(t *testing.T) {
	got, invalid := parseEggRequirements([]byte{'i', 'd', 'n', 'a', 0xff})
	if got != nil || !reflect.DeepEqual(invalid, []int{0}) {
		t.Fatalf("invalid egg-info encoding accepted: got=%#v invalid=%#v", got, invalid)
	}
}

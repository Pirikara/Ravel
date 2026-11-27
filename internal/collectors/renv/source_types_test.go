package renv

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestRecordedRemoteTypes(t *testing.T) {
	for _, tc := range []struct{ source, remoteType, vcs string }{
		{"GitHub", "", "git"},
		{"Git", "git", "git"},
		{"GitLab", "gitlab", "git"},
		{"Bitbucket", "bitbucket", "git"},
		{"Other", "svn", "svn"},
		{"Other", "unrecognized", ""},
		{"Other", "", ""},
	} {
		t.Run(tc.source+"/"+tc.remoteType, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "renv.lock")
			data, err := json.Marshal(map[string]any{"Packages": map[string]any{"example": map[string]string{
				"Package": "example", "Version": "1.2.3", "Source": tc.source,
				"RemoteType": tc.remoteType, "RemoteUrl": "https://code.example.test/team/repository",
				"RemoteSha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			}}})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(file, data, 0o600); err != nil {
				t.Fatal(err)
			}
			doc, err := CollectLock(file, "sample")
			if err != nil || len(doc.Origins) != 1 || doc.Origins[0].VCSType != tc.vcs {
				t.Fatalf("declared remote type changed: %#v %v", doc.Origins, err)
			}
		})
	}
}

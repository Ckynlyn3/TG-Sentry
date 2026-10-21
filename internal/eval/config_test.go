package eval

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func gitTest(t *testing.T, root string, args ...string) string {
	t.Helper()
	c := exec.Command("git", append([]string{"-C", root}, args...)...)
	c.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_AUTHOR_NAME=Synthetic", "GIT_AUTHOR_EMAIL=synthetic@example.invalid", "GIT_COMMITTER_NAME=Synthetic", "GIT_COMMITTER_EMAIL=synthetic@example.invalid")
	b, e := c.CombinedOutput()
	if e != nil {
		t.Fatalf("git %s: %s", args, b)
	}
	return strings.TrimSpace(string(b))
}
func TestFreezeRefusals(t *testing.T) {
	root := t.TempDir()
	gitTest(t, root, "init")
	os.Mkdir(filepath.Join(root, "eval"), 0700)
	os.WriteFile(filepath.Join(root, "code.go"), []byte("original"), 0600)
	gitTest(t, root, "add", ".")
	gitTest(t, root, "commit", "-m", "synthetic baseline")
	gitTest(t, root, "tag", FreezeTag)
	if _, err := CheckGit(root); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(root, "untracked"), []byte("dirty"), 0600)
	if _, err := CheckGit(root); err == nil {
		t.Fatal("dirty tree accepted")
	}
	os.Remove(filepath.Join(root, "untracked"))
	os.WriteFile(filepath.Join(root, "eval/manifest.lock.json"), []byte("lock"), 0600)
	gitTest(t, root, "add", ".")
	gitTest(t, root, "commit", "-m", "lock only")
	if _, err := CheckGit(root); err != nil {
		t.Fatal("lock descendant", err)
	}
	os.WriteFile(filepath.Join(root, "code.go"), []byte("changed"), 0600)
	gitTest(t, root, "add", ".")
	gitTest(t, root, "commit", "-m", "code drift")
	if _, err := CheckGit(root); err == nil {
		t.Fatal("code descendant accepted")
	}
}
func TestStrictLoadAndHash(t *testing.T) {
	var m Manifest
	for _, s := range []string{`{"version":1,"surprise":true}`, `{} {}`, `null`} {
		if Decode(strings.NewReader(s), &m) == nil {
			t.Fatal(s)
		}
	}
	root := t.TempDir()
	p := filepath.Join(root, "fake.json")
	os.WriteFile(p, []byte("synthetic"), 0600)
	h, n, err := HashFile(p)
	if err != nil || n != 9 {
		t.Fatal(h, n, err)
	}
	files := []LockedFile{{Path: "fake.json", SHA256: h, Bytes: n}}
	if _, err := VerifyFiles(root, files); err != nil {
		t.Fatal(err)
	}
	files[0].SHA256 = strings.Repeat("0", 64)
	if _, err := VerifyFiles(root, files); err == nil {
		t.Fatal("hash mismatch accepted")
	}
	files[0].Path = "../fake.json"
	if _, err := VerifyFiles(root, files); err == nil {
		t.Fatal("escape")
	}
	files[0].Path = "link"
	os.Symlink(p, filepath.Join(root, "link"))
	if _, err := VerifyFiles(root, files); err == nil {
		t.Fatal("symlink")
	}
	if err := CheckDigests(map[string]string{"model": h}, map[string]string{"model": strings.Repeat("a", 64)}); err == nil {
		t.Fatal("config drift")
	}
	if err := CheckDigests(map[string]string{"model": h}, map[string]string{"model": h}); err != nil {
		t.Fatal(err)
	}
}

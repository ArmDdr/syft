package testutil

import (
	"github.com/anchore/syft/syft/pkg/cataloger/binary/test-fixtures/manager/internal"
	"github.com/anchore/syft/syft/pkg/cataloger/binary/test-fixtures/manager/internal/config"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
)

// SnippetOrBinary returns the path to either the binary or the snippet for the given logical entry key.
// Note: this is intended to be used only within the context of the binary cataloger test fixtures. Any other
// use is unsupported. Path should be a logical path relative to the test-fixtures/classifiers directory (but does
// not specify the "bin" or "snippets" parent path... this is determined logically [snippets > binary unless told
// otherwise]). Path should also be to the directory containing the binary or snippets of interest (not the binaries
// or snippets itself).
func SnippetOrBinary(t *testing.T, path string, requireBinary bool) string {
	t.Helper()

	require.Len(t, internal.SplitFilepath(path), 3, "path must be a in the form <name>/<version>/<arch>")

	// cd to test-fixtures directory and load the config

	cwd, err := os.Getwd()
	require.NoError(t, err)

	require.NoError(t, os.Chdir("test-fixtures"))
	defer func() {
		require.NoError(t, os.Chdir(cwd))
	}()

	appConfig, err := config.Read()
	require.NoError(t, err)

	// find the first matching fixture path that matches the given requirements

	entries, err := internal.ListAllEntries(*appConfig)
	require.NoError(t, err)

	var fixturePath string
	for k, v := range entries {
		if filepath.Dir(k.Path()) == path {
			// prefer the snippet over the binary
			if !requireBinary {
				if v.SnippetPath != "" {
					t.Logf("using snippet for %q", path)
					validateSnippet(t, v.BinaryPath, v.SnippetPath)
					fixturePath = v.SnippetPath
					break
				}
				if v.BinaryPath != "" {
					fixturePath = v.BinaryPath
					break
				}
				t.Fatalf("no binary or snippet found for %q", path)
			}
			if v.BinaryPath != "" {
				t.Logf("forcing the use of the original binary for %q", path)
				fixturePath = v.BinaryPath
				break
			}

			t.Fatalf("no binary found for %q", path)
		}
	}

	if fixturePath == "" {
		t.Fatalf("no fixture found for %q", path)
	}

	// this should be relative to the tests-fixtures directory and should be the directory containing the binary or
	// snippet of interest (not the path to the binary or snippet itself)
	return filepath.Join("test-fixtures", filepath.Dir(fixturePath))
}

func validateSnippet(t *testing.T, binaryPath, snippetPath string) {
	t.Helper()

	// get a sha256 of the binary
	if _, err := os.Stat(binaryPath); err != nil {
		// no binary to validate against (this is ok)
		return
	}

	metadata, err := internal.ReadSnippetMetadata(snippetPath)
	require.NoError(t, err)

	if metadata == nil {
		return
	}

	f, err := os.Open(binaryPath)
	require.NoError(t, err)
	expected, err := internal.Sha256SumFile(f)
	require.NoError(t, err)

	require.Equal(t, expected, metadata.FileSha256, "snippet shadows a binary with a different sha256")

}

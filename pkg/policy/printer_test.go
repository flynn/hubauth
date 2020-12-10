package policy

import (
	"io/ioutil"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPrintTemplateGolden(t *testing.T) {
	files, err := filepath.Glob("./testdata/printer/*.golden")
	require.NoError(t, err)

	for _, f := range files {
		src, err := ioutil.ReadFile(f)
		require.NoError(t, err)

		golden := string(src)
		d, err := Parse(strings.NewReader(golden))
		require.NoError(t, err)

		out, err := Print(d)
		require.NoError(t, err)
		require.Equal(t, golden, out)
	}
}

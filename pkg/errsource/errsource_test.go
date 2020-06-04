package errsource

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/exp/errors/fmt"
)

func TestFormat(t *testing.T) {
	err := fmt.Errorf("test")
	res := Source(err)
	require.Equal(t, "github.com/flynn/hubauth/pkg/errsource.TestFormat", res.Function)
	require.Regexp(t, "(.+)pkg/errsource/errsource_test\\.go", res.File)
	require.Equal(t, 11, res.Line)
}

package errstack

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/exp/errors/fmt"
)

func TestFormat(t *testing.T) {
	err := fmt.Errorf("test")
	res := string(Format(err))
	require.Regexp(t, "\\Agoroutine 1 \\[running\\]:\ngithub\\.com/flynn/hubauth/pkg/errstack\\.TestFormat\\(\\)\n\t(.+)pkg/errstack/errstack_test\\.go:11 \\+0\\z", res)
}

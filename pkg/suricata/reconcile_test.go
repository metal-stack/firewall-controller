package suricata

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_reconcileDropRulesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "suricata", "drop.conf")

	// no rules and no file is a noop
	changed, err := reconcileDropRulesFile(path, nil)
	require.NoError(t, err)
	require.False(t, changed)
	require.NoFileExists(t, path)

	// rules get written sorted and deduplicated
	changed, err = reconcileDropRulesFile(path, []string{"re:Dshield Block Listed Source", " 2402000 ", "2402000", ""})
	require.NoError(t, err)
	require.True(t, changed)

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, dropConfHeader+"2402000\nre:Dshield Block Listed Source\n", string(content))

	// same rules in a different order do not change anything
	changed, err = reconcileDropRulesFile(path, []string{"2402000", "re:Dshield Block Listed Source"})
	require.NoError(t, err)
	require.False(t, changed)

	// removing all rules removes the file
	changed, err = reconcileDropRulesFile(path, []string{})
	require.NoError(t, err)
	require.True(t, changed)
	require.NoFileExists(t, path)

	// invalid rules are rejected
	_, err = reconcileDropRulesFile(path, []string{"2402000\n# injected"})
	require.Error(t, err)
	_, err = reconcileDropRulesFile(path, []string{"# 2402000"})
	require.Error(t, err)
}

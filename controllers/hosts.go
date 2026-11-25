package controllers

import (
	"fmt"
	"os"

	"github.com/txn2/txeh"
)

// NewHostsFile returns a hosts file editor for the given path, creating the file if it does not exist.
// The returned editor is safe for concurrent use and should be shared between all reconcilers
// that manipulate the same hosts file, otherwise they overwrite each other's entries on save.
func NewHostsFile(path string) (*txeh.Hosts, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		empty, err := os.Create(path)
		if err != nil {
			return nil, err
		}
		_ = empty.Close()
	}

	hosts, err := txeh.NewHosts(&txeh.HostsConfig{
		ReadFilePath:  path,
		WriteFilePath: path,
	})
	if err != nil {
		return nil, fmt.Errorf("unable to create hosts editor: %w", err)
	}

	return hosts, nil
}

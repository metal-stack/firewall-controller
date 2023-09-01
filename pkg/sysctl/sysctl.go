package sysctl

import (
	"os"
	"path"
	"strconv"
	"strings"
)

const (
	sysctlBase = "/proc/sys"
	// NFConntrackMax defines how many connection track entries can be active at the same time
	NFConntrackMax = "/net/netfilter/nf_conntrack_max"
	// NFConntrackMaxSetting defines the maximum settable
	NFConntrackMaxSetting = 4194304
)

// Get returns the value for the specified sysctl setting
func Get(sysctl string) (int, error) {
	data, err := os.ReadFile(path.Join(sysctlBase, sysctl))
	if err != nil {
		return -1, err
	}
	val, err := strconv.Atoi(strings.Trim(string(data), " \n"))
	if err != nil {
		return -1, err
	}
	return val, nil
}

// Set modifies the specified sysctl flag to the new value
func Set(sysctl string, newVal int) error {
	return os.WriteFile(path.Join(sysctlBase, sysctl), []byte(strconv.Itoa(newVal)), 0600)
}

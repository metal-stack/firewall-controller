package sysctl

import (
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"

	"go.uber.org/zap"
)

const (
	// sysctlBase is the root directory for sysctl values in the proc filesystem
	sysctlBase = "/proc/sys"
	// NFConntrackMax defines how many connection track entries can be active at the same time
	NFConntrackMax = Sysctl("/net/netfilter/nf_conntrack_max")
	// NFConntrackMaxSetting defines the maximum settable
	NFConntrackMaxSetting = 4194304

	// moduleBase is the root directory for module specific settings
	moduleBase = "/sys/module"
	// NFConntrackHashSize defines the hashsize of the conntrack module
	NFConntrackHashSize = Module("/nf_conntrack/parameters/hashsize")
	// NFConntrackHashSizeSetting defines the maximum settable
	NFConntrackHashSizeSetting = 4194304
)

type (
	Sysctl string
	Module string
)

func Tune(log *zap.SugaredLogger) error {
	log.Infow("set sysctl value", "key", NFConntrackMax, "value", NFConntrackMaxSetting)
	err := Set(NFConntrackMax, NFConntrackMaxSetting)
	if err != nil {
		return fmt.Errorf("unable to set value of %q %w", NFConntrackMax, err)
	}
	conntrackMax, err := Get(NFConntrackMax)
	if err != nil {
		return fmt.Errorf("unable to get value of %q %w", NFConntrackMax, err)
	}
	log.Infow("set module value", "key", NFConntrackHashSize, "value", NFConntrackHashSizeSetting)
	err = SetModule(NFConntrackHashSize, NFConntrackHashSizeSetting)
	if err != nil {
		return fmt.Errorf("unable to set module parameter %w", err)
	}
	if err != nil {
		return fmt.Errorf("unable to get value of %q %w", NFConntrackMax, err)
	}
	hashSize, err := GetModule(NFConntrackHashSize)
	if err != nil {
		return fmt.Errorf("unable to get value of %q %w", NFConntrackMax, err)
	}

	log.Infow("sysctl and module parameters set", "conntrack max", conntrackMax, "hash size", hashSize)
	return nil
}

// Get returns the value for the specified sysctl setting
func Get(sysctl Sysctl) (int, error) {
	data, err := os.ReadFile(path.Join(sysctlBase, string(sysctl)))
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
func Set(sysctl Sysctl, newVal int) error {
	return os.WriteFile(path.Join(sysctlBase, string(sysctl)), []byte(strconv.Itoa(newVal)), 0600)
}

// GetModule returns the value for the specified Module setting
func GetModule(module Module) (int, error) {
	data, err := os.ReadFile(path.Join(moduleBase, string(module)))
	if err != nil {
		return -1, err
	}
	val, err := strconv.Atoi(strings.Trim(string(data), " \n"))
	if err != nil {
		return -1, err
	}
	return val, nil
}

// SetModule modifies the specified module flag to the new value
func SetModule(module Module, newVal int) error {
	return os.WriteFile(path.Join(moduleBase, string(module)), []byte(strconv.Itoa(newVal)), 0600)
}

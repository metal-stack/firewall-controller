package nftables

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

func uniqueSorted(elements []string) []string {
	t := map[string]bool{}
	for _, e := range elements {
		t[e] = true
	}
	r := []string{}
	for k := range t {
		r = append(r, k)
	}
	sort.Strings(r)
	return r
}

func equal(source, target string) bool {
	sourceChecksum, err := checksum(source)
	if err != nil {
		return false
	}

	targetChecksum, err := checksum(target)
	if err != nil {
		return false
	}

	return bytes.Equal(sourceChecksum, targetChecksum)
}

func checksum(file string) ([]byte, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}

	defer func() {
		_ = f.Close()
	}()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

func assembleDestinationPortRule(common []string, protocol string, ports []string, comment string) string {
	parts := common
	parts = append(parts, fmt.Sprintf("%s dport { %s }", protocol, strings.Join(ports, ", ")))
	parts = append(parts, "counter")
	parts = append(parts, "accept")
	if comment != "" {
		parts = append(parts, "comment", fmt.Sprintf(`"%s"`, comment))
	}
	return strings.Join(parts, " ")
}

func proto(p *corev1.Protocol) string {
	proto := "tcp"
	if p != nil {
		proto = strings.ToLower(string(*p))
	}
	return proto
}

type diffResult struct {
	toAdd    []string
	toRemove []string
}

// diff computes the symmetrical distance of the two string arrays split into elements needed to be added / removed from the current list
func diff(desired, current []string) diffResult {
	res := diffResult{}
	desiredMap := map[string]bool{}
	for _, d := range desired {
		desiredMap[d] = true
	}

	currentMap := map[string]bool{}
	for _, a := range current {
		currentMap[a] = true
	}

	for desired := range desiredMap {
		if !currentMap[desired] {
			res.toAdd = append(res.toAdd, desired)
		}
	}

	for current := range currentMap {
		if !desiredMap[current] {
			res.toRemove = append(res.toRemove, current)
		}
	}

	return res
}

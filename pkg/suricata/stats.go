package suricata

import (
	"bufio"
	"io/ioutil"
	"strconv"
	"strings"
)

type Suricata struct {
	stats string
}

type Stats map[string]int64

func New(stats string) Suricata {
	return Suricata{stats: stats}
}

func (s *Suricata) Stats() (Stats, error) {
	content, err := ioutil.ReadFile(s.stats)
	if err != nil {
		return nil, err
	}
	return parseStats(string(content)), nil
}

func parseStats(stats string) Stats {
	result := Stats{}
	scanner := bufio.NewScanner(strings.NewReader(stats))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "-") {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) != 3 {
			continue
		}
		// Counter                                       | TM Name                   | Value
		// ------------------------------------------------------------------------------------
		// capture.kernel_packets                        | Total                     | 2
		if strings.TrimSpace(parts[1]) != "Total" {
			continue
		}
		value, err := strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
		if err != nil {
			continue
		}
		result[strings.TrimSpace(parts[0])] = value
	}
	return result
}

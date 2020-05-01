package trafficcontrol

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

const (
	tcCommand   = "tc"
	KindTbf     = "tbf"
	KindNoqueue = "noqueue"
)

// Tc manage traffic control rules.
type Tc struct {
	path string
}

// ShowResult is the object to map tc qdisc show output to.
type ShowResult []ShowElement

// ShowElement is a single element for ShowResult.
type ShowElement struct {
	Kind       string  `json:"kind"`
	Handle     string  `json:"handle"`
	Root       bool    `json:"root"`
	Refcnt     uint64  `json:"refcnt"`
	Options    Options `json:"options"`
	Bytes      uint64  `json:"bytes"`
	Packets    uint64  `json:"packets"`
	Drops      uint64  `json:"drops"`
	Overlimits uint64  `json:"overlimits"`
	Requeues   uint64  `json:"requeues"`
	Backlog    uint64  `json:"backlog"`
	Qlen       uint64  `json:"qlen"`
}

// Options are the rule options.
type Options struct {
	Rate uint64 `json:"rate"`
}

// New creates a new traffic controller for nics.
func New() (*Tc, error) {
	path, err := exec.LookPath(tcCommand)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to locate program:%s in path", tcCommand)
	}
	return &Tc{
		path: path,
	}, nil
}

// Show lists the tc rules applied at the interface.
// tc -s -j -d qdisc show dev wlp61s0
// [{"kind":"tbf","handle":"8001:","root":true,"refcnt":2,"options":{"rate":1250,"burst":"1000b/1","mpu":0,"lat":49600,"linklayer":"ethernet"},"bytes":119651
// ,"packets":876,"drops":1436,"overlimits":2836,"requeues":0,"backlog":0,"qlen":0}]
func (tc *Tc) Show(ifacename string) (ShowResult, error) {
	_, err := net.InterfaceByName(ifacename)
	if err != nil {
		return nil, fmt.Errorf("could not find interfaces %v", ifacename)
	}

	out, err := exec.Command(tc.path, "-s", "-j", "-d", "qdisc", "show", "dev", ifacename).CombinedOutput()
	if err != nil {
		return nil, errors.Wrapf(err, "unable to execute %s show", tcCommand)
	}

	var sr ShowResult
	err = json.Unmarshal([]byte(out), &sr)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to parse %s output", tcCommand)
	}
	return sr, nil
}

// ShowTbfRule shows the tbf rule for an interface.
func (tc *Tc) ShowTbfRule(ifacename string) (*ShowElement, error) {
	show, err := tc.Show(ifacename)
	if err != nil {
		return nil, fmt.Errorf("could not gather tc stats for iface %s", ifacename)
	}
	if len(show) == 0 {
		return nil, fmt.Errorf("no tc rules defined for iface %s", ifacename)
	}
	s := show[0]
	if s.Kind != "tbf" {
		return nil, fmt.Errorf("no tbf rule defined for iface %s", ifacename)
	}
	return &s, nil
}

// AddRateLimit adds a rate limit to the given interface.
// tc qdisc add dev wlp61s0 root tbf rate 1gbit burst 100mbit
func (tc *Tc) AddRateLimit(ifacename, rate string) error {
	args := []string{"qdisc", "add", "dev", ifacename, "root", KindTbf, "rate", rate, "burst", "100mbit", "latency", "500ms"}
	out, err := exec.Command(tc.path, args...).CombinedOutput()
	if err != nil {
		return errors.Wrapf(err, "unable to execute %s add, output: %s", tcCommand, string(out))
	}
	return nil
}

// HasRateLimit checks whether the given interface has the given limit.
func (tc *Tc) HasRateLimit(ifacename, rate string) (bool, error) {
	sr, err := tc.Show(ifacename)
	if err != nil {
		return false, err
	}

	if len(sr) == 1 && sr[0].Kind == KindNoqueue {
		return false, nil
	}

	byteRate := rateStringToBytes(rate)
	for _, s := range sr {
		if s.Kind == KindTbf && byteRate == s.Options.Rate {
			return true, nil
		}
	}
	return false, nil
}

// Clear deletes the traffic control rules for a given nic.
// After that the result of tc qdisc show dev x should yield:
// [{"kind":"noqueue","handle":"0:","root":true,"refcnt":2,"options":{},"bytes":0,"packets":0,"drops":0,"overlimits":0,"requeues":0,"backlog":0,"qlen":0}]
func (tc *Tc) Clear(ifacename string) error {
	sr, err := tc.Show(ifacename)
	if err != nil {
		return err
	}

	if len(sr) == 1 && sr[0].Kind == KindNoqueue {
		return nil
	}

	for _, s := range sr {
		err = tc.deleteWithHandle(ifacename, s.Handle)
		if err != nil {
			return err
		}
	}
	return nil
}

// tc qdisc del root dev wlp61s0
func (tc *Tc) deleteWithHandle(ifacename, handle string) error {
	err := exec.Command(tc.path, "qdisc", "del", "root", "handle", handle, "dev", ifacename).Run()
	if err != nil {
		return errors.Wrapf(err, "unable to execute %s del", tcCommand)
	}
	return nil
}

func rateStringToBytes(rateString string) uint64 {
	r := strings.ToLower(rateString)

	if strings.HasSuffix(r, "kbit") {
		return mustExtractInt(r, "kbit") * 1000 / 8
	} else if strings.HasSuffix(r, "mbit") {
		return mustExtractInt(r, "mbit") * 1000000 / 8
	} else if strings.HasSuffix(r, "gbit") {
		return mustExtractInt(r, "gbit") * 1000000000 / 8
	} else {
		return mustExtractInt(r, "") / 8
	}
}

func mustExtractInt(rate, rateUnit string) uint64 {
	soleUnit := strings.TrimSuffix(rate, rateUnit)
	i, _ := strconv.ParseUint(soleUnit, 10, 64)
	return i
}

func main() {
	tc, err := New()
	if err != nil {
		fmt.Printf("err, %v", err)
		os.Exit(1)
	}

	err = tc.Clear("wlp61s0")
	if err != nil {
		fmt.Printf("err, %v", err)
		os.Exit(1)
	}

	r, err := tc.Show("wlp61s0")
	if err != nil {
		fmt.Printf("err, %v", err)
		os.Exit(1)
	}
	fmt.Printf("%v\n", r)

	err = tc.AddRateLimit("wlp61s0", "1gbit")
	if err != nil {
		fmt.Printf("err, %v", err)
		os.Exit(1)
	}

	fmt.Println("show")
	r, err = tc.Show("wlp61s0")
	if err != nil {
		fmt.Printf("err, %v", err)
		os.Exit(1)
	}
	fmt.Printf("%v\n", r)

	has, err := tc.HasRateLimit("wlp61s0", "1gbit")
	if err != nil {
		fmt.Printf("err, %v", err)
		os.Exit(1)
	}
	fmt.Printf("has, %v\n", has)

	err = tc.Clear("wlp61s0")
	if err != nil {
		fmt.Printf("err, %v", err)
		os.Exit(1)
	}

	r, err = tc.Show("wlp61s0")
	if err != nil {
		fmt.Printf("err, %v", err)
		os.Exit(1)
	}
	fmt.Printf("%v\n", r)
}

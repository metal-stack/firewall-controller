package collector

import (
	"bytes"
	"fmt"

	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/go-logr/logr"
	"github.com/google/nftables"

	"github.com/google/nftables/expr"

	firewallv2 "github.com/metal-stack/firewall-controller-manager/api/v2"
)

type (
	// nfCollector collect nftables counter values via netlink
	nfCollector struct {
		logger logr.Logger
	}
)

var (
	countersToCollect = map[string][]string{
		"internal": {"in", "out"},
		"external": {"in", "out"},
	}
	tableName = "firewall"
)

// NewNFTablesCollector create a new Collector for nftables counters
func NewNFTablesCollector(logger *logr.Logger) nfCollector {
	var log logr.Logger
	if logger == nil {
		log = ctrl.Log.WithName("collector")
	} else {
		log = *logger
	}
	return nfCollector{
		logger: log,
	}
}

// Collect nftables counters with netlink
func (n nfCollector) CollectDeviceStats() (firewallv2.DeviceStatsByDevice, error) {
	deviceStatsByDevice := firewallv2.DeviceStatsByDevice{}

	for device, directions := range countersToCollect {
		deviceStat := firewallv2.DeviceStat{}
		for _, direction := range directions {
			countername := device + "_" + direction
			counter, err := getCounter(countername, tableName)
			if err != nil {
				n.logger.Error(err, "unable to gather nftables counter")
				continue
			}
			switch direction {
			case "in":
				deviceStat.InBytes = counter.Bytes
			case "out":
				deviceStat.OutBytes = counter.Bytes
			}

		}
		n.logger.Info("collectdevicestats", "device", device, "stats", deviceStat)
		deviceStatsByDevice[device] = deviceStat
	}

	return deviceStatsByDevice, nil
}

// getCounter queries nftables via netlink and read the a named counter in the given table
// this is equivalent to the cli call
// nft list counter ip tablename countername
func getCounter(countername, tablename string) (*firewallv2.Counter, error) {
	c := nftables.Conn{}
	table := &nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   tablename,
	}
	counterObj := &nftables.CounterObj{
		Table: table,
		Name:  countername,
	}

	obj, err := c.GetObject(counterObj)
	if err != nil {
		return nil, fmt.Errorf("unable to get counter:%s in table:%s obj:%w", countername, tablename, err)
	}
	counter, ok := obj.(*nftables.CounterObj)
	if !ok {
		return nil, fmt.Errorf("unable to read bytes from counter")
	}
	return &firewallv2.Counter{Bytes: counter.Bytes, Packets: counter.Packets}, nil
}

func (n nfCollector) CollectRuleStats() firewallv2.RuleStatsByAction {
	c := nftables.Conn{}
	statsByAction := firewallv2.RuleStatsByAction{
		"accept": firewallv2.RuleStats{},
		"drop":   firewallv2.RuleStats{},
		"other":  firewallv2.RuleStats{},
	}
	chains, _ := c.ListChains()
	for _, chain := range chains {
		rules, _ := c.GetRules(chain.Table, chain)
		for _, r := range rules {
			ri := extractRuleInfo(r)
			if ri == nil {
				continue
			}

			stats := statsByAction[ri.action]
			stat, ok := stats[ri.comment]
			if !ok {
				stat = firewallv2.RuleStat{
					Counter: firewallv2.Counter{},
				}
			}

			stat.Counter = ri.counter
			stats[ri.comment] = stat
			statsByAction[ri.action] = stats
		}
	}

	return statsByAction
}

type ruleInfo struct {
	comment string
	counter firewallv2.Counter
	action  string
}

// extractRuleInfo extracts the rule comment, action and counter from a nftables rule object
func extractRuleInfo(r *nftables.Rule) *ruleInfo {
	if len(r.UserData) < 3 {
		return nil
	}

	comment := string(bytes.Trim(r.UserData[2:], "\x00"))
	var counter *expr.Counter
	var verdict *expr.Verdict

	for _, e := range r.Exprs {
		if v, ok := e.(*expr.Verdict); ok {
			verdict = v
		}
		if c, ok := e.(*expr.Counter); ok {
			counter = c
		}
	}

	if counter == nil {
		return nil
	}

	action := getAction(verdict)
	if action == "" {
		return nil
	}

	return &ruleInfo{
		comment: comment,
		counter: firewallv2.Counter{
			Bytes:   counter.Bytes,
			Packets: counter.Packets,
		},
		action: action,
	}
}

// getAction translates a nftables verdict
func getAction(v *expr.Verdict) string {
	if v == nil {
		return "other"
	}
	switch v.Kind {
	case expr.VerdictAccept:
		return "accept"
	case expr.VerdictDrop:
		return "drop"
	}
	return "other"
}

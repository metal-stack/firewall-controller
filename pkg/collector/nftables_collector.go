package collector

import (
	"fmt"

	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/go-logr/logr"
	"github.com/google/nftables"
)

type (
	// nfCollector collect nftables counter values via netlink
	nfCollector struct {
		logger logr.Logger
	}
)

var (
	countersToCollect = map[string][]string{
		"internal": {"total"},
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

// Collect metrics from node-exporter
func (c nfCollector) Collect() (*DeviceStats, error) {
	stats := DeviceStats{}
	for device, directions := range countersToCollect {
		stat := DeviceStat{}
		for _, direction := range directions {
			countername := device + "_" + direction
			counter, err := getCounter(countername, tableName)
			if err != nil {
				c.logger.Error(err, "unable to gather nftables counter")
				continue
			}
			stat[countername] = counter.Bytes
		}
		stats[device] = stat
	}

	return &stats, nil
}

// Counter holds values of a nftables counter object
type Counter struct {
	Bytes   uint64
	Packets uint64
}

// getCounter queries nftables via netlink and read the a named counter in the given table
// this is equivalent to the cli call
// nft list counter ip tablename countername
func getCounter(countername, tablename string) (*Counter, error) {

	c := nftables.Conn{}
	table := &nftables.Table{
		Family: nftables.TableFamilyIPv4,
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
	return &Counter{Bytes: counter.Bytes, Packets: counter.Packets}, nil
}

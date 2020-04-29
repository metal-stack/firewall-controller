package nftables

import (
	"io"
	"io/ioutil"
	"net/http"
	"strings"

	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/go-logr/logr"
	firewallv1 "github.com/metal-stack/firewall-builder/api/v1"
	"github.com/prometheus/prometheus/pkg/labels"
	"github.com/prometheus/prometheus/pkg/textparse"
)

type (
	// Collector scrapes the node-exporter
	Collector struct {
		logger logr.Logger
		url    string
	}
)

var (
	seriesToCollect = map[string]string{
		"nftables_rule_packets": "packets",
		"nftables_rule_bytes":   "bytes",
	}
)

// NewCollector create a new Collector
func NewCollector(logger *logr.Logger, url string) Collector {
	var log logr.Logger
	if logger == nil {
		log = ctrl.Log.WithName("collector")
	} else {
		log = *logger
	}
	return Collector{
		logger: log,
		url:    url,
	}
}

// Collect metrics from nftables-exporter
func (c Collector) Collect() (firewallv1.RuleStatsByAction, error) {
	resp, err := http.Get(c.url)
	if err != nil {
		c.logger.Error(err, "unable to get metrics from nftables-exporter")
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		c.logger.Error(err, "unable to consume metrics")
		return nil, err
	}

	parser := textparse.NewPromParser(body)

	statsByAction := firewallv1.RuleStatsByAction{}
	for {
		et, err := parser.Next()
		if err == io.EOF {
			break
		}
		if et != textparse.EntrySeries {
			continue
		}
		m, _, v := parser.Series()
		useSeries := false
		for k := range seriesToCollect {
			if strings.HasPrefix(string(m), k) {
				useSeries = true
				continue
			}
		}
		if !useSeries {
			continue
		}
		var lbls labels.Labels
		parser.Metric(&lbls)

		seriesName := ""
		ruleName := ""
		action := ""
		for _, l := range lbls {
			if l.Name == labels.MetricName {
				seriesName = seriesToCollect[l.Value]
			}
			if l.Name == "comment" {
				ruleName = l.Value
			}
			if l.Name == "action" {
				action = l.Value
			}
		}
		if ruleName == "empty" {
			continue
		}

		var stats firewallv1.RuleStats
		if sba, ok := statsByAction[action]; ok {
			stats = sba
		} else {
			stats = firewallv1.RuleStats{}
		}

		var stat firewallv1.RuleStat
		ds, ok := stats[ruleName]
		if !ok {
			stat = firewallv1.RuleStat{
				Counters: map[string]int64{},
			}
		} else {
			stat = ds
		}
		stat.Counters[seriesName] = int64(v)
		stats[ruleName] = stat
		statsByAction[action] = stats
	}
	return statsByAction, nil
}

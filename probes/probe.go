package probes

import (
	"errors"
	"github.com/samber/lo"
	"io"
	"sort"
)

var tcpProbes = make(map[string]*Probe)
var udpProbes = make(map[string]*Probe)

func Init(src io.Reader) error {
	config, err := Parse(src)
	if err != nil {
		return err
	}
	for _, probe := range config.Probes {
		switch probe.Protocol {
		case "tcp":
			tcpProbes[probe.Name] = probe
		case "udp":
			udpProbes[probe.Name] = probe
		default:
			return errors.New("unknown protocol: " + probe.Protocol)
		}
	}
	return nil
}

func GetTcpProbe(name string) *Probe {
	return tcpProbes[name]
}

func GetByPort(port int) []*Probe {
	var result ProbeArray
	for _, p := range tcpProbes {
		if lo.Contains(p.Ports, port) {
			result = append(result, p)
		}
	}
	sort.Sort(result)
	return result

}

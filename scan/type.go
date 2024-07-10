package scan

import (
	"crypto/x509"
	"github.com/raylax/savvy/log"
)

var logger = log.Root.With("module", "scan")

type Stat struct {
	ExecuteRules []string
}

type Result struct {
	Certs      []*x509.Certificate
	SSL        bool
	Banner     string
	Service    string
	Product    string
	Version    string
	Info       string
	Hostname   string
	OS         string
	DeviceType string
	CEPs       []string
	Fallback   bool
}

func (r *Result) String() string {
	s := "[" + r.Service + "]"
	if r.Product != "" {
		s += " product:" + r.Product
	}
	if r.Version != "" {
		s += " version:" + r.Version
	}
	if r.Info != "" {
		s += " info:" + r.Info
	}
	if r.Hostname != "" {
		s += " hostname:" + r.Hostname
	}
	if r.OS != "" {
		s += " os:" + r.OS
	}
	if r.DeviceType != "" {
		s += " deviceType:" + r.DeviceType
	}
	if len(r.CEPs) > 0 {
		s += " ceps:" + r.CEPs[0]
		for i := 1; i < len(r.CEPs); i++ {
			s += "," + r.CEPs[i]
		}
	}

	return s
}

type connectError struct {
	err error
}

func (e *connectError) Error() string {
	return "connect error: " + e.err.Error()
}

type HostScanResult struct {
	IP       string
	Protocol string
	Ports    []int
}

package scan

import (
	"context"
	"fmt"
	"github.com/raylax/masscan"
	"github.com/raylax/masscan/tools"
	"github.com/raylax/savvy/rule"
	"github.com/samber/lo"
	"time"
)

type HostScanner struct {
	Timeout time.Duration
}

func NewHostScanner() *HostScanner {
	return &HostScanner{Timeout: 10 * time.Minute}
}

func (s *HostScanner) ScanTcp(ctx context.Context, ips []string) ([]*HostScanResult, error) {
	var ports []string
	for _, sp := range rule.GetTcpServicePorts() {
		ports = append(ports, fmt.Sprintf("%d", sp.Port))
	}

	ctx, cancel := context.WithTimeout(ctx, s.Timeout)
	defer cancel()

	scanner, err := masscan.NewScanner(
		masscan.SetParams("--randomize-hosts", "--open-only"),
		masscan.SetParamTargets(ips...),
		masscan.SetParamPorts(ports...),
		masscan.EnableDebug(),
		masscan.SetParamWait(0),
		masscan.SetParamRate(5000),
		masscan.WithContext(ctx),
	)

	if err != nil {
		return nil, err
	}

	scanResult, _, err := scanner.Run()
	return collectMasscanResult("tcp", scanResult, err)
}

func (s *HostScanner) ScanUdp(ctx context.Context, ips []string) ([]*HostScanResult, error) {
	var ports []string
	for _, sp := range rule.GetUdpServicePorts()[:500] {
		ports = append(ports, fmt.Sprintf("%d", sp.Port))
	}

	ctx, cancel := context.WithTimeout(ctx, s.Timeout)
	defer cancel()

	scanner, err := masscan.NewScanner(
		masscan.SetParams("-sU", "--randomize-hosts", "--open-only"),
		masscan.SetParamWait(0),
		masscan.SetParamRate(100),
		masscan.SetParamTargets(ips...),
		masscan.SetParamPorts(ports...),
		masscan.WithContext(ctx),
	)

	if err != nil {
		return nil, err
	}

	scanResult, _, err := scanner.Run()
	return collectMasscanResult("udp", scanResult, err)
}

func collectMasscanResult(protocol string, scanResult *tools.MasscanResult, err error) ([]*HostScanResult, error) {

	if err != nil {
		return nil, err
	}

	if scanResult == nil {
		return nil, nil
	}

	var resultMap = make(map[string]*HostScanResult)
	for i, host := range scanResult.Hosts {
		r, ok := resultMap[host.IP]
		if !ok {
			r = &HostScanResult{
				IP:       host.IP,
				Protocol: protocol,
			}
			resultMap[host.IP] = r
		}
		port := scanResult.Ports[i]
		r.Ports = append(r.Ports, port.Port)
	}

	return lo.Values(resultMap), nil
}

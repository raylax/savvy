package probes

type PortRange struct {
	Protocol string
	Ports    []int
}

type Config struct {
	Exclude []*PortRange
	Probes  []*Probe
}

type ProbeMatch struct {
	Service           string
	Pattern           Pattern
	VendorProductName string
	Version           string
	Info              string
	Hostname          string
	OperatingSystem   string
	DeviceType        string
	CPEs              []string
}

type Probe struct {
	Protocol     string
	Name         string
	Data         string
	NoPayload    bool
	TotalWaitMs  int
	TCPWrappedMs int
	Rarity       int
	Ports        []int
	SSLPorts     []int
	Matches      []*ProbeMatch
	SoftMatches  []*ProbeMatch
	Fallbacks    []string
	Options      map[string]string
}

type ProbeArray []*Probe

func (p ProbeArray) Len() int {
	return len(p)
}

func (p ProbeArray) Swap(i, j int) {
	p[i], p[j] = p[j], p[i]
}

func (p ProbeArray) Less(i, j int) bool {
	return p[i].Rarity < p[j].Rarity
}

type Pattern struct {
	Regex   string
	Options string
}

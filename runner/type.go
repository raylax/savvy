package runner

type ServiceDetectionMessage struct {
	ID       string `json:"id"`
	Protocol string `json:"protocol"`
	IP       string `json:"ip"`
	Port     int    `json:"port"`
}

type ServiceDetectionResultMessage struct {
	ID      string                               `json:"id"`
	IP      string                               `json:"ip"`
	Port    int                                  `json:"port"`
	Service ServiceDetectionServiceResultMessage `json:"service"`
}

type ServiceDetectionServiceResultMessage struct {
	SSL        bool
	Certs      []string
	Banner     string
	Service    string
	Product    string
	Version    string
	Info       string
	Hostname   string
	OS         string
	DeviceType string
	CEPs       []string
}

type HostDetectionMessage struct {
	ID       string   `json:"id"`
	IPs      []string `json:"ips"`
	Protocol string   `json:"protocol"`
}

type HostDetectionResultMessage struct {
	ID    string                           `json:"id"`
	Hosts []HostDetectionHostResultMessage `json:"hosts"`
}

type HostDetectionHostResultMessage struct {
	IP       string `json:"ip"`
	Protocol string `json:"protocol"`
	Ports    []int  `json:"ports"`
}

type WorkerGroup struct {
	sem chan struct{}
}

func NewWorkerGroup(num int) *WorkerGroup {
	return &WorkerGroup{sem: make(chan struct{}, num)}
}

func (w *WorkerGroup) Execute(f func()) {
	w.sem <- struct{}{}
	go func() {
		f()
		<-w.sem
	}()
}

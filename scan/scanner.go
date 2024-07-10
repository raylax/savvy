package scan

import (
	"github.com/raylax/savvy/rule"
	"github.com/raylax/savvy/types"
	"slices"
	"strings"
)

const (
	defaultTcpConnectTimeoutMs = 3000
	defaultTcpSendTimeoutMs    = 3000
	defaultTcpReadTimeoutMs    = 3000
	defaultTcpReadBufferSize   = 4096
	defaultTcpExecuteSleepMs   = 1000

	defaultUdpReadTimeoutMs  = 3000
	defaultUdpReadBufferSize = 2048
)

const tcpMaxMatchRules = 7
const udpMaxMatchRules = 10

type TcpOptions struct {
	ConnectTimeoutMs int
	SendTimeoutMs    int
	ReadTimeoutMs    int
	ReadBufferSize   int
	ExecuteSleepMs   int
}

type UdpOptions struct {
	ReadTimeoutMs  int
	ReadBufferSize int
}

type Scanner interface {
	Scan(task *types.Task) (Stat, *Result, error)
}

func NewTcpScanner(options TcpOptions) Scanner {
	if options.ConnectTimeoutMs <= 0 {
		options.ConnectTimeoutMs = defaultTcpConnectTimeoutMs
	}
	if options.SendTimeoutMs <= 0 {
		options.SendTimeoutMs = defaultTcpSendTimeoutMs
	}
	if options.ReadTimeoutMs <= 0 {
		options.ReadTimeoutMs = defaultTcpReadTimeoutMs

	}
	if options.ReadBufferSize <= 0 {
		options.ReadBufferSize = defaultTcpReadBufferSize

	}
	if options.ExecuteSleepMs <= 0 {
		options.ExecuteSleepMs = defaultTcpExecuteSleepMs
	}
	return &tcpScanner{
		options: options,
	}
}

func NewUdpScanner(options UdpOptions) Scanner {
	if options.ReadTimeoutMs <= 0 {
		options.ReadTimeoutMs = defaultUdpReadTimeoutMs
	}
	if options.ReadBufferSize <= 0 {
		options.ReadBufferSize = defaultUdpReadBufferSize

	}
	return &udpScanner{
		options: options,
	}
}

func pushFallbacks(r *rule.TaskRule, rules rule.Queue) {
	if r.Fallbacks == "" {
		return
	}

	fallbacks := strings.Split(r.Fallbacks, ",")
	slices.Reverse(fallbacks)
	for _, fallback := range fallbacks {
		fallbackRule := rules.Find(fallback)
		if fallbackRule == nil {
			continue
		}
		rules.PushFront(fallbackRule)
	}
}

package log

import (
	"log/slog"
	"os"
)

var hostname = ""

func getHostname() string {
	if hostname == "" {
		if h, err := os.Hostname(); err == nil {
			hostname = h
		}
	}
	return hostname
}

var options = &slog.HandlerOptions{
	Level: slog.LevelDebug,
	ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
		if a.Key == "hostname" {
			a.Value = slog.StringValue(getHostname())
		}
		return a
	},
}
var root = slog.New(slog.NewTextHandler(os.Stdout, options)).With("hostname", "")

func NewLogger(args ...any) *slog.Logger {
	return root.With(args...)
}

var Root = root.With("module", "root")

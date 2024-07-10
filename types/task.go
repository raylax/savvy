package types

import (
	"context"
	"log/slog"
)

type Task struct {
	IP     string
	Port   int
	Ctx    context.Context
	Logger *slog.Logger
}

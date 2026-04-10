package main

import (
	"context"
	"log/slog"
)

// teeSlogHandler forwards each record to two handlers (e.g. stderr JSON + OTLP).
type teeSlogHandler struct {
	a, b slog.Handler
}

func newTeeSlogHandler(a, b slog.Handler) slog.Handler {
	return &teeSlogHandler{a: a, b: b}
}

func (t *teeSlogHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return t.a.Enabled(ctx, level) || t.b.Enabled(ctx, level)
}

func (t *teeSlogHandler) Handle(ctx context.Context, r slog.Record) error {
	_ = t.a.Handle(ctx, r)
	return t.b.Handle(ctx, r)
}

func (t *teeSlogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return newTeeSlogHandler(t.a.WithAttrs(attrs), t.b.WithAttrs(attrs))
}

func (t *teeSlogHandler) WithGroup(name string) slog.Handler {
	return newTeeSlogHandler(t.a.WithGroup(name), t.b.WithGroup(name))
}

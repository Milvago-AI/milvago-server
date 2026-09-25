//go:build !commercial

package app

import (
	"context"

	"github.com/prometheus/client_golang/prometheus"
)

type exportMetricSnapshot struct{}
type exportHTTPClient struct{}

func (a *App) CloseExportConnections() {
	// Community does not allocate export connections.
}

func (a *App) RunExports(context.Context) {
	// Community does not run export workers.
}
func (a *App) RefreshExportMetrics(context.Context) error { return nil }
func (a *App) registerExportMetrics(*prometheus.Registry) {
	// Community does not register export metrics.
}

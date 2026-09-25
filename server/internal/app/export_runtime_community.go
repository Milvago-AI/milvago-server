//go:build !commercial

package app

import (
	"context"

	"github.com/prometheus/client_golang/prometheus"
)

type exportMetricSnapshot struct{}
type exportHTTPClient struct{}

func (a *App) CloseExportConnections() {}

func (a *App) RunExports(context.Context)                 {}
func (a *App) RefreshExportMetrics(context.Context) error { return nil }
func (a *App) registerExportMetrics(*prometheus.Registry) {}

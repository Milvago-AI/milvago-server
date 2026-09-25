//go:build hpa_lab

// This binary is built only into the isolated laboratory fixture image.
package main

import (
	"context"
	"flag"
	"log"
	"milvago/server/internal/app"
	"os"
	"time"
)

func main() {
	action := flag.String("action", env("FIXTURE_ACTION", "seed"), "seed, exports, disable-exports, report")
	output := flag.String("output", env("FIXTURE_OUTPUT", "/out/fixture.json"), "private result file")
	ready := flag.String("ready", "", "path to touch once the action has completed, for the pod's readiness probe")
	hold := flag.Duration("hold", 0, "sleep this long after completion, keeping the pod alive for exec/log access")
	probeReady := flag.String("probe-ready", "", "check that this file exists and exit 0/1; used as the readiness probe command itself, since the distroless image running this binary has no shell and no test(1)")
	dump := flag.String("dump", "", "print this file to stdout and exit; used by `kubectl exec` to read the result back out, since the distroless image running this binary has no cat(1) or tar(1) (the latter also rules out `kubectl cp`)")
	flag.Parse()
	if *probeReady != "" {
		if _, err := os.Stat(*probeReady); err != nil {
			os.Exit(1)
		}
		return
	}
	if *dump != "" {
		data, err := os.ReadFile(*dump)
		if err != nil {
			log.Fatal(err)
		}
		os.Stdout.Write(data)
		return
	}
	cfg, err := app.LoadConfig()
	if err != nil {
		log.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if err = app.HPALabFixture(ctx, cfg, *action, *output); err != nil {
		log.Fatal(err)
	}
	log.Printf("synthetic HPA fixture action %s completed", *action)
	if *ready != "" {
		if err := os.WriteFile(*ready, nil, 0o644); err != nil {
			log.Fatal(err)
		}
	}
	if *hold > 0 {
		time.Sleep(*hold)
	}
}
func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"flag"
	"log/slog"
	"os"
	"runtime/pprof"

	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/benchmark"
	"github.com/cilium/cilium/pkg/logging"
)

// Test size is the number of services. Each service has a single EndpointSlice.
var testSize = flag.Int("services", 50000, "number of services to create")
var podsPerService = flag.Int("pods-per-service", 1, "number of backend pods to create per service")
var enableLRP = flag.Bool("enable-lrp", false, "create a node-local-dns LRP for each service")
var lrpSharedNamespace = flag.Bool("lrp-shared-namespace", false, "place all LRP benchmark objects in one namespace")
var iterations = flag.Int("iterations", 10, "number of benchmark runs to perform")

// Small workloads may not fill the reflector event buffer. In that case, the
// production default can dominate the reported reconciliation time. Use 10ms
// when measuring reconciliation work rather than batching latency.
var reflectorWaitTime = flag.Duration("reflector-wait-time", loadbalancer.DefaultUserConfig.ReflectorWaitTime, "maximum time the loadbalancer reflector waits before emitting a partial event batch")

var cpuprofile = flag.String("cpuprofile", "", "write cpu profile to `file`")
var loglevel = flag.String("log-level", "error", "log-level")
var validate = flag.Bool("validate", false, "validate results (load test rather than benchmark)")

func main() {
	flag.Parse()

	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			logging.Fatal(slog.Default(), "could not create CPU profile: ", err)
		}
		defer f.Close()
		if err := pprof.StartCPUProfile(f); err != nil {
			logging.Fatal(slog.Default(), "could not start CPU profile: ", err)
		}
		defer pprof.StopCPUProfile()
	}
	var level slog.Level
	if err := level.UnmarshalText([]byte(*loglevel)); err != nil {
		panic(err)
	}
	benchmark.RunBenchmark(benchmark.Config{
		Services:           *testSize,
		PodsPerService:     *podsPerService,
		Iterations:         *iterations,
		LRPEnabled:         *enableLRP,
		LRPSharedNamespace: *lrpSharedNamespace,
		ReflectorWaitTime:  *reflectorWaitTime,
		LogLevel:           level,
		Validate:           *validate,
	})
}

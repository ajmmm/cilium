// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package benchmark_test

import (
	"log/slog"
	"testing"

	"github.com/cilium/cilium/pkg/loadbalancer/benchmark"
	"github.com/cilium/cilium/pkg/time"
)

// TestBenchmark validates that RunBenchmark() compiles and works, but only
// does one iteration and thus this is not a benchmark itself.
// run "go run ./cmd" for a proper benchmark run.
func TestBenchmark(t *testing.T) {
	// Keep these functional tests from waiting for the production batching interval.
	t.Run("without LRP", func(t *testing.T) {
		benchmark.RunBenchmark(benchmark.Config{
			Services:          1,
			PodsPerService:    2,
			Iterations:        1,
			ReflectorWaitTime: 10 * time.Millisecond,
			LogLevel:          slog.LevelError,
			Validate:          true,
		})
	})

	t.Run("with LRP", func(t *testing.T) {
		benchmark.RunBenchmark(benchmark.Config{
			Services:          1,
			PodsPerService:    2,
			Iterations:        1,
			LRPEnabled:        true,
			ReflectorWaitTime: 10 * time.Millisecond,
			LogLevel:          slog.LevelError,
			Validate:          true,
		})
	})

	t.Run("with LRP in shared namespace", func(t *testing.T) {
		benchmark.RunBenchmark(benchmark.Config{
			Services:           2,
			PodsPerService:     2,
			Iterations:         1,
			LRPEnabled:         true,
			LRPSharedNamespace: true,
			ReflectorWaitTime:  10 * time.Millisecond,
			LogLevel:           slog.LevelError,
			Validate:           true,
		})
	})
}

// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package bpf

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"iter"
	"log/slog"
	"math"
	"os"
	"path"
	"reflect"
	"strings"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/spanstat"
	"github.com/cilium/cilium/pkg/time"
)

var (
	// ErrMaxLookup is returned when the maximum number of map element lookups has
	// been reached.
	ErrMaxLookup = errors.New("maximum number of lookups reached")

	bpfMapSyncControllerGroup = controller.NewGroup("bpf-map-sync")
)

type MapKey interface {
	fmt.Stringer

	// New must return a pointer to a new MapKey.
	New() MapKey
}

type MapValue interface {
	fmt.Stringer

	// New must return a pointer to a new MapValue.
	New() MapValue
}

// MapPerCPUValue is the same as MapValue, but for per-CPU maps. Implement to be
// able to fetch map values from all CPUs.
type MapPerCPUValue interface {
	MapValue

	// NewSlice must return a pointer to a slice of structs that implement MapValue.
	NewSlice() any
}

type cacheEntry struct {
	Key   MapKey
	Value MapValue

	DesiredAction DesiredAction
	LastError     error
}

type Map struct {
	Logger *slog.Logger
	m      *ebpf.Map
	// spec will be nil after the map has been created
	spec *ebpf.MapSpec

	key   MapKey
	value MapValue

	name string
	path string
	lock lock.RWMutex

	// cachedCommonName is the common portion of the name excluding any
	// endpoint ID
	cachedCommonName string

	// enableSync is true when synchronization retries have been enabled.
	enableSync bool

	// withValueCache is true when map cache has been enabled
	withValueCache bool

	// cache as key/value entries when map cache is enabled or as key-only when
	// pressure metric is enabled
	cache map[string]*cacheEntry

	// errorResolverLastScheduled is the timestamp when the error resolver
	// was last scheduled
	errorResolverLastScheduled time.Time

	// outstandingErrors states whether there are outstanding errors, occurred while
	// syncing an entry with the kernel, that need to be resolved. This variable exists
	// to avoid iterating over the full cache to check if reconciliation is necessary,
	// but it is possible that it gets out of sync if an error is automatically
	// resolved while performing a subsequent Update/Delete operation on the same key.
	outstandingErrors bool

	// pressureGauge is a metric that tracks the pressure on this map
	pressureGauge *metrics.GaugeWithThreshold

	// is true when events buffer is enabled.
	eventsBufferEnabled bool

	// contains optional event buffer which stores last n bpf map events.
	events *eventsBuffer

	// group is the metric group name for this map, it classifies maps of the same
	// type that share the same metric group.
	group string
}

func (m *Map) Type() ebpf.MapType {
	if m.m != nil {
		return m.m.Type()
	}
	if m.spec != nil {
		return m.spec.Type
	}
	return ebpf.UnspecifiedMap
}

type nopDecoder []struct{}

func (nopDecoder) UnmarshalBinary(data []byte) error {
	return nil
}

// BatchCount the number of elements in the map using a batch lookup.
// Only usable for hash, lru-hash and lpm-trie maps.
func (m *Map) BatchCount() (count int, err error) {
	switch m.Type() {
	case ebpf.Hash, ebpf.LRUHash, ebpf.LPMTrie:
		break
	default:
		return 0, fmt.Errorf("unsupported map type %s, must be one either hash or lru-hash types", m.Type())
	}
	chunkSize := startingChunkSize(int(m.MaxEntries()))

	// Since we don't care about the actual data we just use a no-op binary
	// decoder.
	keys := make(nopDecoder, chunkSize)
	vals := make(nopDecoder, chunkSize)
	maxRetries := defaultBatchedRetries

	var cursor ebpf.MapBatchCursor
	for {
		for retry := range maxRetries {
			// Attempt to read batch into buffer.
			c, batchErr := m.BatchLookup(&cursor, keys, vals, nil)
			count += c

			switch {
			// Lookup batch on LRU hash map may fail if the buffer passed is not big enough to
			// accommodate the largest bucket size in the LRU map. See full comment in
			// [BatchIterator.IterateAll]
			case errors.Is(batchErr, unix.ENOSPC):
				if retry == maxRetries-1 {
					err = batchErr
				} else {
					chunkSize *= 2
				}
				keys = make(nopDecoder, chunkSize)
				vals = make(nopDecoder, chunkSize)
				continue
			case errors.Is(batchErr, ebpf.ErrKeyNotExist):
				return
			case batchErr != nil:
				// If we're not done, and we didn't hit a ENOSPC then stop iteration and record
				// the error.
				err = fmt.Errorf("failed to iterate map: %w", batchErr)
				return
			}
			// Do the next batch
			break
		}
	}
}

func (m *Map) KeySize() uint32 {
	if m.m != nil {
		return m.m.KeySize()
	}
	if m.spec != nil {
		return m.spec.KeySize
	}
	return 0
}

func (m *Map) ValueSize() uint32 {
	if m.m != nil {
		return m.m.ValueSize()
	}
	if m.spec != nil {
		return m.spec.ValueSize
	}
	return 0
}

func (m *Map) MaxEntries() uint32 {
	if m.m != nil {
		return m.m.MaxEntries()
	}
	if m.spec != nil {
		return m.spec.MaxEntries
	}
	return 0
}

func (m *Map) Flags() uint32 {
	if m.m != nil {
		return m.m.Flags()
	}
	if m.spec != nil {
		return m.spec.Flags
	}
	return 0
}

func (m *Map) hasPerCPUValue() bool {
	mt := m.Type()
	return mt == ebpf.PerCPUHash || mt == ebpf.PerCPUArray || mt == ebpf.LRUCPUHash || mt == ebpf.PerCPUCGroupStorage
}

func (m *Map) updateMetrics() {
	if m.group == "" {
		return
	}
	metrics.UpdateMapCapacity(m.group, m.MaxEntries())
}

// NewMap creates a new Map instance - object representing a BPF map
func NewMap(name string, mapType ebpf.MapType, mapKey MapKey, mapValue MapValue,
	maxEntries int, flags uint32) *Map {

	// slogloggercheck: it's safe to use the default logger here as it has been initialized by the program up to this point.
	defaultSlogLogger := logging.DefaultSlogLogger
	keySize := reflect.TypeOf(mapKey).Elem().Size()
	valueSize := reflect.TypeOf(mapValue).Elem().Size()

	return &Map{
		Logger: defaultSlogLogger.With(
			logfields.BPFMapPath, name,
			logfields.BPFMapName, name,
		),
		spec: &ebpf.MapSpec{
			Type:       mapType,
			Name:       path.Base(name),
			KeySize:    uint32(keySize),
			ValueSize:  uint32(valueSize),
			MaxEntries: uint32(maxEntries),
			Flags:      flags,
		},
		name:  path.Base(name),
		key:   mapKey,
		value: mapValue,
		group: name,
	}
}

// NewMap creates a new Map instance - object representing a BPF map
func NewMapWithInnerSpec(name string, mapType ebpf.MapType, mapKey MapKey, mapValue MapValue,
	maxEntries int, flags uint32, innerSpec *ebpf.MapSpec) *Map {

	// slogloggercheck: it's safe to use the default logger here as it has been initialized by the program up to this point.
	defaultSlogLogger := logging.DefaultSlogLogger
	keySize := reflect.TypeOf(mapKey).Elem().Size()
	valueSize := reflect.TypeOf(mapValue).Elem().Size()

	return &Map{
		Logger: defaultSlogLogger.With(
			logfields.BPFMapPath, name,
			logfields.BPFMapName, name,
		),
		spec: &ebpf.MapSpec{
			Type:       mapType,
			Name:       path.Base(name),
			KeySize:    uint32(keySize),
			ValueSize:  uint32(valueSize),
			MaxEntries: uint32(maxEntries),
			Flags:      flags,
			InnerMap:   innerSpec,
		},
		name:  path.Base(name),
		key:   mapKey,
		value: mapValue,
	}
}

func (m *Map) commonName() string {
	if m.cachedCommonName != "" {
		return m.cachedCommonName
	}

	m.cachedCommonName = extractCommonName(m.name)
	return m.cachedCommonName
}

func (m *Map) NonPrefixedName() string {
	return strings.TrimPrefix(m.name, metrics.Namespace+"_")
}

// scheduleErrorResolver schedules a periodic resolver controller that scans
// all BPF map caches for unresolved errors and attempts to resolve them. On
// error of resolution, the controller is-rescheduled in an expedited manner
// with an exponential back-off.
//
// m.lock must be held for writing
func (m *Map) scheduleErrorResolver() {
	m.outstandingErrors = true

	if time.Since(m.errorResolverLastScheduled) <= errorResolverSchedulerMinInterval {
		return
	}

	m.errorResolverLastScheduled = time.Now()

	go func() {
		time.Sleep(errorResolverSchedulerDelay)
		mapControllers.UpdateController(m.controllerName(),
			controller.ControllerParams{
				Group:       bpfMapSyncControllerGroup,
				DoFunc:      m.resolveErrors,
				RunInterval: errorResolverSchedulerMinInterval,
			},
		)
	}()

}

// WithCache enables use of a cache. This will store all entries inserted from
// user space in a local cache (map) and will indicate the status of each
// individual entry.
func (m *Map) WithCache() *Map {
	if m.cache == nil {
		m.cache = map[string]*cacheEntry{}
	}
	m.withValueCache = true
	m.enableSync = true
	return m
}

// WithEvents enables use of the event buffer, if the buffer is enabled.
// This stores all map events (i.e. add/update/delete) in a bounded event buffer.
// If eventTTL is not zero, than events that are older than the TTL
// will periodically be removed from the buffer.
// Enabling events will use aprox proportional to 100MB for every million capacity
// in maxSize.
//
// TODO: The IPCache map have many periodic update events added by a controller for entries such as the 0.0.0.0/0 range.
// These fill the event buffer with possibly unnecessary events.
// We should either provide an option to aggregate these events, ignore hem from the ipcache event buffer or store them in a separate buffer.
func (m *Map) WithEvents(c option.BPFEventBufferConfig) *Map {
	if !c.Enabled {
		return m
	}
	m.Logger.Debug(
		"enabling events buffer",
		logfields.Size, c.MaxSize,
		logfields.TTL, c.TTL,
	)
	m.eventsBufferEnabled = true
	m.initEventsBuffer(c.MaxSize, c.TTL)
	return m
}

func (m *Map) WithGroupName(group string) *Map {
	m.group = group
	return m
}

// WithPressureMetricThreshold enables the tracking of a metric that measures
// the pressure of this map. This metric is only reported if over the
// threshold.
func (m *Map) WithPressureMetricThreshold(registry *metrics.Registry, threshold float64) *Map {
	if registry == nil {
		return m
	}

	// When pressure metric is enabled, we keep track of map keys in cache
	if m.cache == nil {
		m.cache = map[string]*cacheEntry{}
	}

	m.pressureGauge = registry.NewBPFMapPressureGauge(m.NonPrefixedName(), threshold)

	return m
}

// WithPressureMetric enables tracking and reporting of this map pressure with
// threshold 0.
func (m *Map) WithPressureMetric(registry *metrics.Registry) *Map {
	return m.WithPressureMetricThreshold(registry, 0.0)
}

// UpdatePressureMetricWithSize updates map pressure metric using the given map size.
func (m *Map) UpdatePressureMetricWithSize(size int32) {
	if m.pressureGauge == nil {
		return
	}

	// Do a lazy check of MetricsConfig as it is not available at map static
	// initialization.
	if !metrics.BPFMapPressure {
		if !m.withValueCache {
			m.cache = nil
		}
		m.pressureGauge = nil
		return
	}

	pvalue := float64(size) / float64(m.MaxEntries())
	m.pressureGauge.Set(pvalue)
}

func (m *Map) updatePressureMetric() {
	// Skipping pressure metric gauge updates for LRU map as the cache size
	// does not accurately represent the actual map sie.
	if m.spec != nil && m.spec.Type == ebpf.LRUHash {
		return
	}
	m.UpdatePressureMetricWithSize(int32(len(m.cache)))
}

func (m *Map) FD() int {
	return m.m.FD()
}

// Name returns the basename of this map.
func (m *Map) Name() string {
	return m.name
}

// Path returns the path to this map on the filesystem.
func (m *Map) Path() (string, error) {
	if err := m.setPathIfUnset(); err != nil {
		return "", err
	}

	return m.path, nil
}

// Unpin attempts to unpin (remove) the map from the filesystem.
func (m *Map) Unpin() error {
	path, err := m.Path()
	if err != nil {
		return err
	}

	return os.RemoveAll(path)
}

// UnpinIfExists tries to unpin (remove) the map only if it exists.
func (m *Map) UnpinIfExists() error {
	found, err := m.exist()
	if err != nil {
		return err
	}

	if !found {
		return nil
	}

	return m.Unpin()
}

func (m *Map) controllerName() string {
	return fmt.Sprintf("bpf-map-sync-%s", m.name)
}

// OpenMap opens the map at pinPath.
func OpenMap(pinPath string, key MapKey, value MapValue) (*Map, error) {
	if !path.IsAbs(pinPath) {
		return nil, fmt.Errorf("pinPath must be absolute: %s", pinPath)
	}

	em, err := ebpf.LoadPinnedMap(pinPath, nil)
	if err != nil {
		return nil, err
	}

	// slogloggercheck: it's safe to use the default logger here as it has been initialized by the program up to this point.
	defaultSlogLogger := logging.DefaultSlogLogger

	logger := defaultSlogLogger.With(
		logfields.BPFMapPath, pinPath,
		logfields.BPFMapName, path.Base(pinPath),
	)
	m := &Map{
		Logger: logger,
		m:      em,
		name:   path.Base(pinPath),
		path:   pinPath,
		key:    key,
		value:  value,
	}

	m.updateMetrics()
	registerMap(logger, pinPath, m)

	return m, nil
}

func (m *Map) setPathIfUnset() error {
	if m.path == "" {
		if m.name == "" {
			return fmt.Errorf("either path or name must be set")
		}

		m.path = MapPath(m.Logger, m.name)
	}

	return nil
}

// Recreate removes any pin at the Map's pin path, recreates and re-pins it.
func (m *Map) Recreate() error {
	m.lock.Lock()
	defer m.lock.Unlock()

	if m.m != nil {
		return fmt.Errorf("map already open: %s", m.name)
	}

	if err := m.setPathIfUnset(); err != nil {
		return err
	}

	if err := os.Remove(m.path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("removing pinned map %s: %w", m.name, err)
	}

	m.Logger.Info(
		"Removed map pin, recreating and re-pinning map",
	)

	return m.openOrCreate(true)
}

// IsOpen returns true if the map has been opened.
func (m *Map) IsOpen() bool {
	m.lock.Lock()
	defer m.lock.Unlock()
	return m.m != nil
}

// OpenOrCreate attempts to open the Map, or if it does not yet exist, create
// the Map. If the existing map's attributes such as map type, key/value size,
// capacity, etc. do not match the Map's attributes, then the map will be
// deleted and reopened without any attempt to retain its previous contents.
// If the map is marked as non-persistent, it will always be recreated.
//
// Returns whether the map was deleted and recreated, or an optional error.
func (m *Map) OpenOrCreate() error {
	m.lock.Lock()
	defer m.lock.Unlock()

	return m.openOrCreate(true)
}

// CreateUnpinned creates the map without pinning it to the file system.
//
// TODO(tb): Remove this when all map creation takes MapSpec.
func (m *Map) CreateUnpinned() error {
	m.lock.Lock()
	defer m.lock.Unlock()

	return m.openOrCreate(false)
}

// Create is similar to OpenOrCreate, but closes the map after creating or
// opening it.
func (m *Map) Create() error {
	if err := m.OpenOrCreate(); err != nil {
		return err
	}
	return m.Close()
}

func (m *Map) openOrCreate(pin bool) error {
	if m.m != nil {
		return nil
	}

	if m.spec == nil {
		return fmt.Errorf("attempted to create map %s without MapSpec", m.name)
	}

	if err := m.setPathIfUnset(); err != nil {
		return err
	}

	m.spec.Flags |= GetMapMemoryFlags(m.spec.Type)

	if m.spec.InnerMap != nil {
		m.spec.InnerMap.Flags |= GetMapMemoryFlags(m.spec.InnerMap.Type)
	}

	if pin {
		m.spec.Pinning = ebpf.PinByName
	}

	em, err := OpenOrCreateMap(m.Logger, m.spec, path.Dir(m.path))
	if err != nil {
		return err
	}

	m.updateMetrics()
	registerMap(m.Logger, m.path, m)

	// Consume the MapSpec.
	m.spec = nil

	// Retain the Map.
	m.m = em

	return nil
}

// Open opens the BPF map. All calls to Open() are serialized due to acquiring
// m.lock
func (m *Map) Open() error {
	m.lock.Lock()
	defer m.lock.Unlock()

	return m.open()
}

// open opens the BPF map. It is identical to Open() but should be used when
// m.lock is already held. open() may only be used if m.lock is held for
// writing.
func (m *Map) open() error {
	if m.m != nil {
		return nil
	}

	if err := m.setPathIfUnset(); err != nil {
		return err
	}

	em, err := ebpf.LoadPinnedMap(m.path, nil)
	if err != nil {
		return fmt.Errorf("loading pinned map %s: %w", m.path, err)
	}

	m.updateMetrics()
	registerMap(m.Logger, m.path, m)

	m.m = em

	return nil
}

func (m *Map) Close() error {
	m.lock.Lock()
	defer m.lock.Unlock()

	if m.enableSync {
		mapControllers.RemoveController(m.controllerName())
	}

	if m.m != nil {
		m.m.Close()
		m.m = nil
	}

	unregisterMap(m.Logger, m.path, m)

	return nil
}

func (m *Map) NextKey(key, nextKeyOut any) error {
	var duration *spanstat.SpanStat
	if metrics.BPFSyscallDuration.IsEnabled() {
		duration = spanstat.Start()
	}

	err := m.m.NextKey(key, nextKeyOut)

	if metrics.BPFSyscallDuration.IsEnabled() {
		metrics.BPFSyscallDuration.WithLabelValues(metricOpGetNextKey, metrics.Error2Outcome(err)).Observe(duration.End(err == nil).Total().Seconds())
	}

	return err
}

type DumpCallback func(key MapKey, value MapValue)

// DumpWithCallback iterates over the Map and calls the given DumpCallback for
// each map entry. With the current implementation, it is safe for callbacks to
// retain the values received, as they are guaranteed to be new instances.
//
// To dump per-cpu maps, use DumpPerCPUWithCallback.
func (m *Map) DumpWithCallback(cb DumpCallback) error {
	if cb == nil {
		return errors.New("empty callback")
	}

	if err := m.Open(); err != nil {
		return err
	}

	m.lock.RLock()
	defer m.lock.RUnlock()

	// Don't need deep copies here, only fresh pointers.
	mk := m.key.New()
	mv := m.value.New()

	i := m.m.Iterate()
	for i.Next(mk, mv) {
		cb(mk, mv)

		mk = m.key.New()
		mv = m.value.New()
	}

	return i.Err()
}

// DumpPerCPUCallback is called by DumpPerCPUWithCallback with the map key and
// the slice of all values from all CPUs.
type DumpPerCPUCallback func(key MapKey, values any)

// DumpPerCPUWithCallback iterates over the Map and calls the given
// DumpPerCPUCallback for each map entry, passing the slice with all values
// from all CPUs. With the current implementation, it is safe for callbacks
// to retain the values received, as they are guaranteed to be new instances.
func (m *Map) DumpPerCPUWithCallback(cb DumpPerCPUCallback) error {
	if cb == nil {
		return errors.New("empty callback")
	}

	if !m.hasPerCPUValue() {
		return fmt.Errorf("map %s is not a per-CPU map", m.name)
	}

	v, ok := m.value.(MapPerCPUValue)
	if !ok {
		return fmt.Errorf("map %s value type does not implement MapPerCPUValue", m.name)
	}

	if err := m.Open(); err != nil {
		return err
	}

	m.lock.RLock()
	defer m.lock.RUnlock()

	// Don't need deep copies here, only fresh pointers.
	mk := m.key.New()
	mv := v.NewSlice()

	i := m.m.Iterate()
	for i.Next(mk, mv) {
		cb(mk, mv)

		mk = m.key.New()
		mv = v.NewSlice()
	}

	return i.Err()
}

// DumpWithCallbackIfExists is similar to DumpWithCallback, but returns earlier
// if the given map does not exist.
func (m *Map) DumpWithCallbackIfExists(cb DumpCallback) error {
	found, err := m.exist()
	if err != nil {
		return err
	}

	if found {
		return m.DumpWithCallback(cb)
	}

	return nil
}

// DumpReliablyWithCallback is similar to DumpWithCallback, but performs
// additional tracking of the current and recently seen keys, so that if an
// element is removed from the underlying kernel map during the dump, the dump
// can continue from a recently seen key rather than restarting from scratch.
// In addition, it caps the maximum number of map entry iterations at 4 times
// the maximum map size. If this limit is reached, ErrMaxLookup is returned.
//
// The caller must provide a callback for handling each entry, and a stats
// object initialized via a call to NewDumpStats(). The callback function must
// not invoke any map operations that acquire the Map.lock.
func (m *Map) DumpReliablyWithCallback(cb DumpCallback, stats *DumpStats) error {
	if cb == nil {
		return errors.New("empty callback")
	}

	if stats == nil {
		return errors.New("stats is nil")
	}

	var (
		prevKey    = m.key.New()
		currentKey = m.key.New()
		nextKey    = m.key.New()
		value      = m.value.New()

		prevKeyValid = false
	)

	stats.start()
	defer stats.finish()

	if err := m.Open(); err != nil {
		return err
	}

	// Acquire a (write) lock here as callers can invoke map operations in the
	// DumpCallback that need a (write) lock.
	// See PR for more details. - https://github.com/cilium/cilium/pull/38590.
	m.lock.Lock()
	defer m.lock.Unlock()
	if m.m == nil {
		// We currently don't prevent open maps from being closed.
		// See GH issue - https://github.com/cilium/cilium/issues/39287.
		return errors.New("map is closed")
	}

	// Get the first map key.
	if err := m.NextKey(nil, currentKey); err != nil {
		stats.Lookup = 1
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			// Empty map, nothing to iterate.
			stats.Completed = true
			return nil
		}
	}

	// maxLookup is an upper bound limit to prevent backtracking forever
	// when iterating over the map's elements (the map might be concurrently
	// updated while being iterated)
	maxLookup := stats.MaxEntries * 4

	// This loop stops when all elements have been iterated (Map.NextKey() returns
	// ErrKeyNotExist) OR, in order to avoid hanging if
	// the map is continuously updated, when maxLookup has been reached
	for stats.Lookup = 1; stats.Lookup <= maxLookup; stats.Lookup++ {
		// currentKey was set by the first m.NextKey() above. We know it existed in
		// the map, but it may have been deleted by a concurrent map operation.
		//
		// If currentKey is no longer in the map, nextKey may be the first key in
		// the map again. Continue with nextKey only if we still find currentKey in
		// the Lookup() after the call to m.NextKey(), this way we know nextKey is
		// NOT the first key in the map and iteration hasn't reset.
		nextKeyErr := m.NextKey(currentKey, nextKey)

		if err := m.m.Lookup(currentKey, value); err != nil {
			stats.LookupFailed++
			// Restarting from a invalid key starts the iteration again from the beginning.
			// If we have a previously found key, try to restart from there instead
			if prevKeyValid {
				currentKey = prevKey
				// Restart from a given previous key only once, otherwise if the prevKey is
				// concurrently deleted we might loop forever trying to look it up.
				prevKeyValid = false
				stats.KeyFallback++
			} else {
				// Depending on exactly when currentKey was deleted from the
				// map, nextKey may be the actual key element after the deleted
				// one, or the first element in the map.
				currentKey = nextKey
				// To avoid having nextKey and currentKey pointing at the same memory
				// we allocate a new key for nextKey. Without this currentKey and nextKey
				// would be the same pointer value and would get double iterated on the next
				// iterations m.NextKey(...) call.
				nextKey = m.key.New()
				stats.Interrupted++
			}
			continue
		}

		cb(currentKey, value)

		if nextKeyErr != nil {
			if errors.Is(nextKeyErr, ebpf.ErrKeyNotExist) {
				stats.Completed = true
				return nil // end of map, we're done iterating
			}
			return nextKeyErr
		}

		// Prepare keys to move to the next iteration.
		prevKey = currentKey
		currentKey = nextKey
		nextKey = m.key.New()
		prevKeyValid = true
	}

	return ErrMaxLookup
}

// BatchIterator provides a typed wrapper *Map that allows for batched iteration
// of bpf maps.
type BatchIterator[KT, VT any, KP KeyPointer[KT], VP ValuePointer[VT]] struct {
	m    *Map
	err  error
	keys []KT
	vals []VT

	chunkSize      int
	maxDumpRetries uint32

	// Iteration stats
	batchSize int

	opts *ebpf.BatchOptions
}

// NewBatchIterator that allows for iterating a map using the bpf batch api.
// This automatically handles concerns such as batch sizing and handling errors
// when end of map is reached.
// Following iteration, any unresolved errors encountered when iterating
// the bpf map can be accessed via the Err() function.
// The pointer type of KT & VT must implement Map{Key,Value}, respectively.
//
// Subsequent iterations via IterateAll reset all internal state and begin
// iteration over.
//
// Example usage:
//
//	m := NewMap("cilium_test",
//		ebpf.Hash,
//		&TestKey{}, 	// *TestKey implements MapKey.
//		&TestValue{}, 	// *TestValue implements MapValue.
//		mapSize,
//		BPF_F_NO_PREALLOC,
//	)
//
//	iter := NewBatchIterator[TestKey, TestValue](m)
//	for k, v := range iter.IterateAll(context.TODO()) {
//		// ...
//	}
func NewBatchIterator[KT any, VT any, KP KeyPointer[KT], VP ValuePointer[VT]](m *Map) *BatchIterator[KT, VT, KP, VP] {
	return &BatchIterator[KT, VT, KP, VP]{
		m: m,
	}
}

// KeyPointer is a generic interface that provides the constraint that the pointer
// of a type T is a MapKey.
type KeyPointer[T any] interface {
	MapKey
	*T
}

// ValuePointer is a generic interface that provides the constraint that the pointer
// of a type T is a MapValue.
type ValuePointer[T any] interface {
	MapValue
	*T
}

// Err returns errors encountered during the previous iteration when
// IterateAll(...) is called.
//
// If the iterator is reused, the error will be reset,
func (kvs BatchIterator[KT, VT, KP, VP]) Err() error {
	return kvs.err
}

func (bi BatchIterator[KT, VT, KP, VP]) maxBatchedRetries() int {
	if bi.maxDumpRetries > 0 {
		return int(bi.maxDumpRetries)
	}
	return defaultBatchedRetries
}

const defaultBatchedRetries = 3

type BatchIteratorOpt[KT any, VT any, KP KeyPointer[KT], VP ValuePointer[VT]] func(*BatchIterator[KT, VT, KP, VP]) *BatchIterator[KT, VT, KP, VP]

// WithEBPFBatchOpts returns a batch iterator option that allows for overriding
// BPF_MAP_LOOKUP_BATCH options.
func WithEBPFBatchOpts[KT, VT any, KP KeyPointer[KT], VP ValuePointer[VT]](opts *ebpf.BatchOptions) BatchIteratorOpt[KT, VT, KP, VP] {
	return func(in *BatchIterator[KT, VT, KP, VP]) *BatchIterator[KT, VT, KP, VP] {
		in.opts = opts
		return in
	}
}

// WithMaxRetries returns a batch iterator option that allows overriding the default
// max batch retries.
//
// Unless the starting chunk size is set to be the map size, it is possible for iteration
// to fail with ENOSPC if the passed allocated chunk array size is not big enough to accommodate
// a the bpf maps underlying hashmaps bucket size.
//
// If this happens, BatchIterator will automatically attempt to double the batch size and
// retry the iteration from the same place - up to a number of retries.
func WithMaxRetries[KT, VT any, KP KeyPointer[KT], VP ValuePointer[VT]](retries uint32) BatchIteratorOpt[KT, VT, KP, VP] {
	return func(in *BatchIterator[KT, VT, KP, VP]) *BatchIterator[KT, VT, KP, VP] {
		in.maxDumpRetries = retries
		return in
	}
}

// WithStartingChunkSize returns a batch iterator option that allows overriding the dynamically
// chosen starting chunk size.
func WithStartingChunkSize[KT, VT any, KP KeyPointer[KT], VP ValuePointer[VT]](size int) BatchIteratorOpt[KT, VT, KP, VP] {
	return func(in *BatchIterator[KT, VT, KP, VP]) *BatchIterator[KT, VT, KP, VP] {
		in.chunkSize = size
		if in.chunkSize <= 0 {
			in.chunkSize = 8
		}
		return in
	}
}

// CountAll is a helper function that returns the count of all elements in a batched
// iterator.
func CountAll[KT, VT any, KP KeyPointer[KT], VP ValuePointer[VT]](ctx context.Context, iter *BatchIterator[KT, VT, KP, VP]) (int, error) {
	c := 0
	for range iter.IterateAll(ctx) {
		c++
	}
	return c, iter.Err()
}

func startingChunkSize(maxEntries int) int {
	bucketSize := math.Sqrt(float64(maxEntries * 2))
	nearest2 := math.Log2(bucketSize)
	return int(math.Pow(2, math.Ceil(nearest2)))
}

// IterateAll returns an iterate Seq2 type which can be used to iterate a map
// using the batched API.
// In the case of a the iteration failing due to insufficient batch buffer size,
// this will attempt to grow the buffer by a factor of 2 (up to a default: 3 amount
// of retries) and re-attempt the iteration.
// If the number of failures exceeds max retries, then iteration will stop and an error
// will be returned via Err().
//
// All other errors will result in immediate termination of iterator.
//
// If the iteration fails, then the Err() function will return the error that caused the failure.
func (bi *BatchIterator[KT, VT, KP, VP]) IterateAll(ctx context.Context, opts ...BatchIteratorOpt[KT, VT, KP, VP]) iter.Seq2[KP, VP] {
	switch bi.m.Type() {
	case ebpf.Hash, ebpf.LRUHash, ebpf.LPMTrie:
		break
	default:
		bi.err = fmt.Errorf("unsupported map type %s, must be one either hash or lru-hash types", bi.m.Type())
		return func(yield func(KP, VP) bool) {}
	}

	bi.chunkSize = startingChunkSize(int(bi.m.MaxEntries()))

	for _, opt := range opts {
		if opt != nil {
			bi = opt(bi)
		}
	}

	// reset values
	bi.err = nil
	bi.batchSize = 0
	bi.keys = make([]KT, bi.chunkSize)
	bi.vals = make([]VT, bi.chunkSize)

	processed := 0
	var cursor ebpf.MapBatchCursor
	return func(yield func(KP, VP) bool) {
		if bi.Err() != nil {
			return
		}

	iterate:
		for {
			if ctx.Err() != nil {
				bi.err = ctx.Err()
				return
			}
		retry:
			for retry := range bi.maxBatchedRetries() {
				// Attempt to read batch into buffer.
				c, batchErr := bi.m.BatchLookup(&cursor, bi.keys, bi.vals, nil)
				bi.batchSize = c

				done := errors.Is(batchErr, ebpf.ErrKeyNotExist)
				// Lookup batch on LRU hash map may fail if the buffer passed is not big enough to
				// accommodate the largest bucket size in the LRU map [1]
				// Because bucket size, in general, cannot be known, we approximate a good starting
				// buffer size from the approximation of how many entries there should be in the map
				// before expect to see a hash map collision: sqrt(max_entries * 2)
				//
				// If we receive ENOSPC failures, we will try to recover by growing the batch buffer
				// size (up to some max number of retries - default: 3) and retrying the iteration.
				//
				// [1] https://elixir.bootlin.com/linux/v6.12.6/source/kernel/bpf/hashtab.c#L1807-L1809
				//
				// Note: If this failure happens during the bpf syscall, it is expected that the underlying
				// cursor will not have been swapped - meaning that we can retry the iteration at the same cursor.
				if errors.Is(batchErr, unix.ENOSPC) {
					if retry == bi.maxBatchedRetries()-1 {
						bi.err = batchErr
					} else {
						bi.chunkSize *= 2
						bi.keys = make([]KT, bi.chunkSize)
						bi.vals = make([]VT, bi.chunkSize)
					}
					continue retry
				} else if !done && batchErr != nil {
					// If we're not done, and we didn't hit a ENOSPC then stop iteration and record
					// the error.
					bi.err = fmt.Errorf("failed to iterate map: %w", batchErr)
					return
				}

				// Yield all received pairs.
				for i := range bi.batchSize {
					processed++
					if !yield(&bi.keys[i], &bi.vals[i]) {
						break iterate
					}
				}

				if done {
					break iterate
				}
				break retry // finish retry loop for this batch.
			}
		}
	}
}

// Dump returns the map (type map[string][]string) which contains all
// data stored in BPF map.
func (m *Map) Dump(hash map[string][]string) error {
	callback := func(key MapKey, value MapValue) {
		// No need to deep copy since we are creating strings.
		hash[key.String()] = append(hash[key.String()], value.String())
	}

	if err := m.DumpWithCallback(callback); err != nil {
		return err
	}

	return nil
}

// BatchLookup returns the count of elements in the map by dumping the map
// using batch lookup.
func (m *Map) BatchLookup(cursor *ebpf.MapBatchCursor, keysOut, valuesOut any, opts *ebpf.BatchOptions) (int, error) {
	return m.m.BatchLookup(cursor, keysOut, valuesOut, opts)
}

// DumpIfExists dumps the contents of the map into hash via Dump() if the map
// file exists
func (m *Map) DumpIfExists(hash map[string][]string) error {
	found, err := m.exist()
	if err != nil {
		return err
	}

	if found {
		return m.Dump(hash)
	}

	return nil
}

func (m *Map) Lookup(key MapKey) (MapValue, error) {
	if err := m.Open(); err != nil {
		return nil, err
	}

	m.lock.RLock()
	defer m.lock.RUnlock()

	var duration *spanstat.SpanStat
	if metrics.BPFSyscallDuration.IsEnabled() {
		duration = spanstat.Start()
	}

	value := m.value.New()
	err := m.m.Lookup(key, value)

	if metrics.BPFSyscallDuration.IsEnabled() {
		metrics.BPFSyscallDuration.WithLabelValues(metricOpLookup, metrics.Error2Outcome(err)).Observe(duration.End(err == nil).Total().Seconds())
	}

	if err != nil {
		return nil, err
	}

	return value, nil
}

func (m *Map) Update(key MapKey, value MapValue) error {
	var err error

	m.lock.Lock()
	defer m.lock.Unlock()

	defer func() {
		desiredAction := OK
		if err != nil {
			desiredAction = Insert
		}
		entry := &cacheEntry{
			Key:           key,
			Value:         value,
			DesiredAction: desiredAction,
			LastError:     err,
		}
		m.addToEventsLocked(MapUpdate, *entry)

		if m.cache == nil {
			return
		}

		if m.withValueCache {
			if err != nil {
				m.scheduleErrorResolver()
			}
			m.cache[key.String()] = &cacheEntry{
				Key:           key,
				Value:         value,
				DesiredAction: desiredAction,
				LastError:     err,
			}
			m.updatePressureMetric()
		} else if err == nil {
			m.cache[key.String()] = nil
			m.updatePressureMetric()
		}
	}()

	if err = m.open(); err != nil {
		return err
	}

	err = m.m.Update(key, value, ebpf.UpdateAny)

	if metrics.BPFMapOps.IsEnabled() {
		metrics.BPFMapOps.WithLabelValues(m.commonName(), metricOpUpdate, metrics.Error2Outcome(err)).Inc()
	}

	if err != nil {
		return fmt.Errorf("update map %s: %w", m.Name(), err)
	}

	return nil
}

// deleteMapEvent is run at every delete map event.
// If cache is enabled, it will update the cache to reflect the delete.
// As well, if event buffer is enabled, it adds a new event to the buffer.
func (m *Map) deleteMapEvent(key MapKey, err error) {
	m.addToEventsLocked(MapDelete, cacheEntry{
		Key:           key,
		DesiredAction: Delete,
		LastError:     err,
	})
	m.deleteCacheEntry(key, err)
}

func (m *Map) deleteAllMapEvent() {
	m.addToEventsLocked(MapDeleteAll, cacheEntry{})
}

// deleteCacheEntry evaluates the specified error, if nil the map key is
// removed from the cache to indicate successful deletion. If non-nil, the map
// key entry in the cache is updated to indicate deletion failure with the
// specified error.
//
// Caller must hold m.lock for writing
func (m *Map) deleteCacheEntry(key MapKey, err error) {
	if m.cache == nil {
		return
	}

	k := key.String()
	if err == nil {
		delete(m.cache, k)
	} else if !m.withValueCache {
		return
	} else {
		entry, ok := m.cache[k]
		if !ok {
			m.cache[k] = &cacheEntry{
				Key: key,
			}
			entry = m.cache[k]
		}

		entry.DesiredAction = Delete
		entry.LastError = err
		m.scheduleErrorResolver()
	}
}

// delete deletes the map entry corresponding to the given key. If ignoreMissing
// is set to true and the entry was not found, the error metric is not
// incremented for missing entries and nil error is returned.
func (m *Map) delete(key MapKey, ignoreMissing bool) (_ bool, err error) {
	defer func() {
		m.deleteMapEvent(key, err)
		if err != nil {
			m.updatePressureMetric()
		}
	}()

	if err = m.open(); err != nil {
		return false, err
	}

	var duration *spanstat.SpanStat
	if metrics.BPFSyscallDuration.IsEnabled() {
		duration = spanstat.Start()
	}

	err = m.m.Delete(key)

	if metrics.BPFSyscallDuration.IsEnabled() {
		metrics.BPFSyscallDuration.WithLabelValues(metricOpDelete, metrics.Error2Outcome(err)).Observe(duration.End(err == nil).Total().Seconds())
	}

	if errors.Is(err, ebpf.ErrKeyNotExist) && ignoreMissing {
		// Error and metrics handling is skipped in case ignoreMissing is set and
		// the map key did not exist. This removes false positives in the delete
		// metrics and skips the deferred cleanup of nonexistent entries. This
		// situation occurs at least in the context of cleanup of NAT mappings from
		// CT GC.
		return false, nil
	}

	if metrics.BPFMapOps.IsEnabled() {
		// err can be nil or any error other than ebpf.ErrKeyNotExist.
		metrics.BPFMapOps.WithLabelValues(m.commonName(), metricOpDelete, metrics.Error2Outcome(err)).Inc()
	}

	if err != nil {
		return false, fmt.Errorf("unable to delete element %s from map %s: %w", key, m.name, err)
	}

	return true, nil
}

// SilentDelete deletes the map entry corresponding to the given key.
// If a map entry is not found this returns (false, nil).
func (m *Map) SilentDelete(key MapKey) (deleted bool, err error) {
	m.lock.Lock()
	defer m.lock.Unlock()

	return m.delete(key, true)
}

// Delete deletes the map entry corresponding to the given key.
func (m *Map) Delete(key MapKey) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	_, err := m.delete(key, false)
	return err
}

// DeleteLocked deletes the map entry for the given key.
//
// This method must be called from within a DumpCallback to avoid deadlocks,
// as it assumes the m.lock is already acquired.
func (m *Map) DeleteLocked(key MapKey) error {
	_, err := m.delete(key, false)

	return err
}

// DeleteAll deletes all entries of a map by traversing the map and deleting individual
// entries. Note that if entries are added while the taversal is in progress,
// such entries may survive the deletion process.
func (m *Map) DeleteAll() error {
	m.lock.Lock()
	defer m.lock.Unlock()
	defer m.updatePressureMetric()
	m.Logger.Debug("deleting all entries in map")

	if m.withValueCache {
		// Mark all entries for deletion, upon successful deletion,
		// entries will be removed or the LastError will be updated
		for _, entry := range m.cache {
			entry.DesiredAction = Delete
			entry.LastError = fmt.Errorf("deletion pending")
		}
	}

	if err := m.open(); err != nil {
		return err
	}

	mk := m.key.New()
	mv := make([]byte, m.ValueSize())

	defer m.deleteAllMapEvent()

	i := m.m.Iterate()
	for i.Next(mk, &mv) {
		err := m.m.Delete(mk)

		m.deleteCacheEntry(mk, err)

		if err != nil {
			return err
		}
	}

	err := i.Err()
	if err != nil {
		m.Logger.Warn(
			"Unable to correlate iteration key with cache entry. Inconsistent cache.",
			logfields.Error, err,
			logfields.Key, mk,
		)
	}

	return err
}

func (m *Map) ClearAll() error {
	if m.eventsBufferEnabled || m.withValueCache {
		return fmt.Errorf("clear map: events buffer and value cache are not supported")
	}

	m.lock.Lock()
	defer m.lock.Unlock()
	defer m.updatePressureMetric()

	if err := m.open(); err != nil {
		return err
	}

	mk := m.key.New()
	var mv any
	if m.hasPerCPUValue() {
		mv = m.value.(MapPerCPUValue).NewSlice()
	} else {
		mv = m.value.New()
	}
	empty := reflect.Indirect(reflect.ValueOf(mv)).Interface()

	i := m.m.Iterate()
	for i.Next(mk, mv) {
		err := m.m.Update(mk, empty, ebpf.UpdateAny)

		if metrics.BPFMapOps.IsEnabled() {
			metrics.BPFMapOps.WithLabelValues(m.commonName(), metricOpUpdate, metrics.Error2Outcome(err)).Inc()
		}

		if err != nil {
			return err
		}
	}

	return i.Err()
}

// GetModel returns a BPF map in the representation served via the API
func (m *Map) GetModel() *models.BPFMap {

	mapModel := &models.BPFMap{
		Path: m.path,
	}

	mapModel.Cache = make([]*models.BPFMapEntry, 0, len(m.cache))
	if m.withValueCache {
		m.lock.RLock()
		defer m.lock.RUnlock()
		for k, entry := range m.cache {
			model := &models.BPFMapEntry{
				Key:           k,
				DesiredAction: entry.DesiredAction.String(),
			}

			if entry.LastError != nil {
				model.LastError = entry.LastError.Error()
			}

			if entry.Value != nil {
				model.Value = entry.Value.String()
			}
			mapModel.Cache = append(mapModel.Cache, model)
		}
		return mapModel
	}

	stats := NewDumpStats(m)
	filterCallback := func(key MapKey, value MapValue) {
		mapModel.Cache = append(mapModel.Cache, &models.BPFMapEntry{
			Key:   key.String(),
			Value: value.String(),
		})
	}

	m.DumpReliablyWithCallback(filterCallback, stats)
	return mapModel
}

func (m *Map) addToEventsLocked(action Action, entry cacheEntry) {
	if !m.eventsBufferEnabled {
		return
	}
	m.events.add(&Event{
		action:     action,
		Timestamp:  time.Now(),
		cacheEntry: entry,
	})
}

// resolveErrors is schedule by scheduleErrorResolver() and runs periodically.
// It resolves up to maxSyncErrors discrepancies between cache and BPF map in
// the kernel.
func (m *Map) resolveErrors(ctx context.Context) error {
	started := time.Now()

	m.lock.Lock()
	defer m.lock.Unlock()

	if m.cache == nil {
		return nil
	}

	if !m.outstandingErrors {
		return nil
	}

	outstanding := 0
	for _, e := range m.cache {
		switch e.DesiredAction {
		case Insert, Delete:
			outstanding++
		}
	}

	// Errors appear to have already been resolved. This can happen if a subsequent
	// Update/Delete operation acting on the same key succeeded.
	if outstanding == 0 {
		m.outstandingErrors = false
		return nil
	}

	if err := m.open(); err != nil {
		return err
	}

	m.Logger.Debug(
		"Starting periodic BPF map error resolver",
		logfields.Remaining, outstanding,
	)

	resolved := 0
	scanned := 0
	nerr := 0
	for k, e := range m.cache {
		scanned++

		switch e.DesiredAction {
		case OK:
		case Insert:
			// Call into ebpf-go's Map.Update() directly, don't go through the cache.
			err := m.m.Update(e.Key, e.Value, ebpf.UpdateAny)
			if metrics.BPFMapOps.IsEnabled() {
				metrics.BPFMapOps.WithLabelValues(m.commonName(), metricOpUpdate, metrics.Error2Outcome(err)).Inc()
			}
			if err == nil {
				e.DesiredAction = OK
				e.LastError = nil
				resolved++
				outstanding--
			} else {
				e.LastError = err
				nerr++
			}
			m.cache[k] = e
			m.addToEventsLocked(MapUpdate, *e)
		case Delete:
			// Holding lock, issue direct delete on map.
			err := m.m.Delete(e.Key)
			if metrics.BPFMapOps.IsEnabled() {
				metrics.BPFMapOps.WithLabelValues(m.commonName(), metricOpDelete, metrics.Error2Outcome(err)).Inc()
			}
			if err == nil || errors.Is(err, ebpf.ErrKeyNotExist) {
				delete(m.cache, k)
				resolved++
				outstanding--
			} else {
				e.LastError = err
				nerr++
				m.cache[k] = e
			}

			m.addToEventsLocked(MapDelete, *e)
		}

		// bail out if maximum errors are reached to relax the map lock
		if nerr > maxSyncErrors {
			break
		}
	}

	m.updatePressureMetric()

	m.Logger.Debug(
		"BPF map error resolver completed",
		logfields.Remaining, outstanding,
		logfields.Resolved, resolved,
		logfields.Scanned, scanned,
		logfields.Duration, time.Since(started),
	)

	m.outstandingErrors = outstanding > 0
	if m.outstandingErrors {
		return fmt.Errorf("%d map sync errors", outstanding)
	}

	return nil
}

// CheckAndUpgrade checks the received map's properties (for the map currently
// loaded into the kernel) against the desired properties, and if they do not
// match, deletes the map.
//
// Returns true if the map was upgraded.
func (m *Map) CheckAndUpgrade(desired *Map) bool {
	flags := desired.Flags() | GetMapMemoryFlags(desired.Type())

	return objCheck(
		m.Logger,
		m.m,
		m.path,
		desired.Type(),
		desired.KeySize(),
		desired.ValueSize(),
		desired.MaxEntries(),
		flags,
	)
}

func (m *Map) exist() (bool, error) {
	path, err := m.Path()
	if err != nil {
		return false, err
	}

	if _, err := os.Stat(path); err == nil {
		return true, nil
	}

	return false, nil
}

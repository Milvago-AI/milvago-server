package app

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/tetratelabs/wazero"
)

//go:generate node ../../../scripts/build-discovery.mjs
//go:embed discovery_engine.wasm
var discoveryEngineBinary []byte

var sharedDiscoveryRuntime = sync.OnceValues(func() (*dlpRuntime, error) {
	runtime := wazero.NewRuntimeWithConfig(context.Background(), wazero.NewRuntimeConfig().WithMemoryLimitPages(2048).WithCloseOnContextDone(true))
	compiled, err := runtime.CompileModule(context.Background(), discoveryEngineBinary)
	if err != nil {
		_ = runtime.Close(context.Background())
		return nil, errors.New("discovery engine initialization failed")
	}
	return &dlpRuntime{runtime: runtime, compiled: compiled, capacity: make(chan struct{}, 4)}, nil
})

func discoveryEngine(ctx context.Context, request any, destination any) error {
	input, err := json.Marshal(request)
	if err != nil || len(input) > 2<<20 {
		return bad("Discovery input exceeds its limits.")
	}
	runtime, err := sharedDiscoveryRuntime()
	if err != nil {
		return apiError{503, "discovery_unavailable", "Discovery evaluation is unavailable."}
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	select {
	case runtime.capacity <- struct{}{}:
		defer func() { <-runtime.capacity }()
	case <-ctx.Done():
		return ctx.Err()
	}
	module, err := runtime.runtime.InstantiateModule(ctx, runtime.compiled, wazero.NewModuleConfig().WithName("").WithStartFunctions())
	if err != nil {
		return apiError{503, "discovery_unavailable", "Discovery evaluation is unavailable."}
	}
	defer module.Close(context.Background())
	alloc, call := module.ExportedFunction("discovery_alloc"), module.ExportedFunction("discovery_call")
	if alloc == nil || call == nil || module.Memory() == nil {
		return errors.New("invalid discovery engine exports")
	}
	address, err := alloc.Call(ctx, uint64(len(input)))
	if err != nil || len(address) != 1 || address[0] == 0 || !module.Memory().Write(uint32(address[0]), input) {
		return errors.New("discovery allocation failed")
	}
	packed, err := call.Call(ctx, address[0], uint64(len(input)))
	if err != nil || len(packed) != 1 {
		return errors.New("discovery evaluation failed")
	}
	length, pointer := uint32(packed[0]>>32), uint32(packed[0])
	if length == 0 || length > 2<<20 {
		return errors.New("discovery output limit")
	}
	output, ok := module.Memory().Read(pointer, length)
	if !ok {
		return errors.New("invalid discovery output")
	}
	var status struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if json.Unmarshal(output, &status) != nil {
		return errors.New("invalid discovery output")
	}
	if !status.OK {
		if len(status.Error) > 200 {
			status.Error = "Invalid discovery input."
		}
		return apiError{400, "discovery_invalid", status.Error}
	}
	if destination != nil {
		return json.Unmarshal(output, destination)
	}
	// Closing the instance reclaims both successful outputs and trap/error allocations.
	return nil
}

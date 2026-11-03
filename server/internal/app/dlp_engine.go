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

//go:generate node ../../../scripts/build-dlp.mjs
//go:embed dlp_engine.wasm
var dlpEngineBinary []byte

type dlpRuntime struct {
	runtime  wazero.Runtime
	compiled wazero.CompiledModule
	capacity chan struct{}
}

var sharedDLPRuntime = sync.OnceValues(func() (*dlpRuntime, error) {
	config := wazero.NewRuntimeConfig().WithMemoryLimitPages(1024).WithCloseOnContextDone(true)
	runtime := wazero.NewRuntimeWithConfig(context.Background(), config)
	compiled, err := runtime.CompileModule(context.Background(), dlpEngineBinary)
	if err != nil {
		_ = runtime.Close(context.Background())
		return nil, errors.New("DLP engine could not be initialized")
	}
	return &dlpRuntime{runtime: runtime, compiled: compiled, capacity: make(chan struct{}, 4)}, nil
})

// Each invocation gets fresh linear memory. No guest imports or host resources are exposed.
func dlpEngine(ctx context.Context, request any, destination any) error {
	input, err := json.Marshal(request)
	if err != nil || len(input) > 524288 {
		return bad("DLP input exceeds its limits.")
	}
	runtime, err := sharedDLPRuntime()
	if err != nil {
		return apiError{503, "dlp_unavailable", "DLP inspection is unavailable."}
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	select {
	case runtime.capacity <- struct{}{}:
		defer func() { <-runtime.capacity }()
	case <-ctx.Done():
		return apiError{503, "dlp_unavailable", "DLP inspection is unavailable."}
	}
	module, err := runtime.runtime.InstantiateModule(ctx, runtime.compiled, wazero.NewModuleConfig().WithName("").WithStartFunctions())
	if err != nil {
		return apiError{503, "dlp_unavailable", "DLP inspection is unavailable."}
	}
	defer module.Close(context.Background())
	alloc, call, free := module.ExportedFunction("dlp_alloc"), module.ExportedFunction("dlp_call"), module.ExportedFunction("dlp_free")
	if alloc == nil || call == nil || free == nil || module.Memory() == nil {
		return apiError{503, "dlp_unavailable", "DLP inspection is unavailable."}
	}
	address, err := alloc.Call(ctx, uint64(len(input)))
	if err != nil || len(address) != 1 || address[0] == 0 || !module.Memory().Write(uint32(address[0]), input) {
		return apiError{503, "dlp_unavailable", "DLP inspection is unavailable."}
	}
	packed, err := call.Call(ctx, address[0], uint64(len(input)))
	if err != nil || len(packed) != 1 {
		return apiError{503, "dlp_unavailable", "DLP inspection is unavailable."}
	}
	length, pointer := uint32(packed[0]>>32), uint32(packed[0])
	if length == 0 || length > 1048576 {
		return apiError{503, "dlp_unavailable", "DLP inspection is unavailable."}
	}
	output, ok := module.Memory().Read(pointer, length)
	if !ok {
		return apiError{503, "dlp_unavailable", "DLP inspection is unavailable."}
	}
	var status struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if json.Unmarshal(output, &status) != nil {
		return apiError{503, "dlp_unavailable", "DLP inspection is unavailable."}
	}
	if !status.OK {
		if len(status.Error) > 300 {
			status.Error = "DLP input was rejected."
		}
		return apiError{400, "dlp_invalid", status.Error}
	}
	if destination != nil {
		if err = json.Unmarshal(output, destination); err != nil {
			return apiError{503, "dlp_unavailable", "DLP inspection is unavailable."}
		}
	}
	_, err = free.Call(ctx, uint64(pointer), uint64(length))
	if err != nil {
		return apiError{503, "dlp_unavailable", "DLP inspection is unavailable."}
	}
	return nil
}

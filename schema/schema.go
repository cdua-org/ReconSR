// Package schema defines the core data structures and interfaces shared across ReconSR components.
package schema

import "time"

// ===================================================================================
// Data Transfer Objects (DTOs) for inter-component communication
// ===================================================================================

// Entity is a typed data unit in the system (e.g., domain, ip, email).
type Entity struct {
	Type     string   `json:"Type,omitempty"`
	Category string   `json:"Category,omitempty"`
	Value    string   `json:"Value"`
	Tags     []string `json:"Tags,omitempty"`
}

// EntityRef represents a reference to an entity.
type EntityRef struct {
	Type    string `json:"Type"`
	Value   string `json:"Value"`
	Anchor  string `json:"Anchor,omitempty"`
	LocalID int `json:"LocalID,omitempty"`
}

type ModuleFunction struct {
	ModuleName string `json:"ModuleName"`
	Function   string `json:"Function"`
}

type RepoToDispatcherBatchItem struct {
	SourceEntityID     int64            `json:"SourceEntityID"`
	Entity             Entity           `json:"Entity"`
	OutOfScope         bool             `json:"OutOfScope"`
	DepthStrict        int              `json:"DepthStrict"`
	DepthRelaxed       int              `json:"DepthRelaxed"`
	CompletedFunctions []ModuleFunction `json:"CompletedFunctions"`
}

type RepoToDispatcherData struct {
	ProjectID string                      `json:"ProjectID"`
	Batch     []RepoToDispatcherBatchItem `json:"Batch"`
}

// ModuleInput is sent from the Dispatcher to a Module.
type ModuleInput struct {
	Target    Entity   `json:"Target"`
	Functions []string `json:"Functions"`
}

// ModuleResult represents a single result from a module's execution.
type ModuleResult struct {
	Type       string     `json:"Type"`
	Category   string     `json:"Category,omitempty"`
	Value      string     `json:"Value"`
	Context    string     `json:"Context,omitempty"`
	Source     *EntityRef `json:"Source,omitempty"`
	LocalID    int     `json:"LocalID,omitempty"`
	Applied    bool       `json:"Applied,omitempty"`
	OutOfScope bool       `json:"OutOfScope,omitempty"`
	Tags       []string   `json:"Tags,omitempty"`
}

// ModuleExecution holds results of a single function call.
type ModuleExecution struct {
	Function string         `json:"Function"`
	Results  []ModuleResult `json:"Results"`
	RawData  string         `json:"RawData"`
	Error    *string        `json:"Error"`
}

// ModuleOutput is sent from a Module to the Dispatcher.
type ModuleOutput struct {
	Executions []ModuleExecution `json:"Executions"`
}

type DispatcherToProcessorData struct {
	ProjectID    string            `json:"ProjectID"`
	ModuleName   string            `json:"ModuleName"`
	SourceEntity Entity            `json:"SourceEntity"`
	Executions   []ModuleExecution `json:"Executions"`
}

// ProcessorInputResult is a single entity found by a module function.
type ProcessorInputResult struct {
	Type       string     `json:"Type"`
	Category   string     `json:"Category,omitempty"`
	Value      string     `json:"Value"`
	Context    string     `json:"Context"`
	Source     *EntityRef `json:"Source,omitempty"`
	LocalID    int     `json:"LocalID,omitempty"`
	Applied    bool       `json:"Applied,omitempty"`
	OutOfScope bool       `json:"OutOfScope,omitempty"`
	Tags       []string   `json:"Tags,omitempty"`
}

// ProcessorInputExecution groups results of one function call with its raw output and error.
type ProcessorInputExecution struct {
	Function string                 `json:"Function"`
	Results  []ProcessorInputResult `json:"Results"`
	RawData  string                 `json:"RawData,omitempty"`
	Error    *string                `json:"Error,omitempty"`
}

// ProcessorInputError is a system-level error (e.g., timeout) attached before module execution.
type ProcessorInputError struct {
	Function string `json:"Function"`
	Type     string `json:"Type"`
	Text     string `json:"Text"`
}

// ProcessorInputData is the unified input sent to the Processor from any source.
type ProcessorInputData struct {
	ProjectID          string                    `json:"ProjectID"`
	ModuleName         string                    `json:"ModuleName"`
	SourceEntityID     int64                     `json:"SourceEntityID"`
	SourceEntity       Entity                    `json:"SourceEntity"`
	Executions         []ProcessorInputExecution `json:"Executions"`
	RequestedFunctions []string                  `json:"RequestedFunctions,omitempty"`
	FunctionInputTypes map[string][]string       `json:"FunctionInputTypes,omitempty"`
	Errors             []ProcessorInputError     `json:"Errors,omitempty"`
}

// PipelineInjection carries the initial user input into the pipeline loop.
type PipelineInjection struct {
	ToProcessor  *ProcessorInputData
	ToDispatcher *RepoToDispatcherData
}

type ProcessorToRepoValidResult struct {
	Function   string   `json:"Function"`
	Type       string   `json:"Type"`
	Category   string   `json:"Category,omitempty"`
	Value      string   `json:"Value"`
	Context    string   `json:"Context"`
	Applied    bool     `json:"Applied,omitempty"`
	OutOfScope bool     `json:"OutOfScope,omitempty"`
	Tags       []string `json:"Tags,omitempty"`
	Anchor     string   `json:"Anchor,omitempty"`
	LocalID    int   `json:"LocalID,omitempty"`
}

type ProcessorToRepoError struct {
	Function  string `json:"Function"`
	ErrorType string `json:"ErrorType"`
	ErrorText string `json:"ErrorText"`
}

type ResultGroup struct {
	Source  EntityRef                    `json:"Source"`
	Results []ProcessorToRepoValidResult `json:"Results"`
}

type ProcessorToRepoData struct {
	ProjectID               string                 `json:"ProjectID"`
	ModuleName              string                 `json:"ModuleName"`
	SourceEntityID          int64                  `json:"SourceEntityID"`
	SourceEntity            Entity                 `json:"SourceEntity"`
	Groups                  []ResultGroup          `json:"Groups"`
	FunctionsWithoutResults []string               `json:"FunctionsWithoutResults"`
	FunctionRawData         map[string]string      `json:"FunctionRawData,omitempty"`
	Errors                  []ProcessorToRepoError `json:"Errors"`
}

type NodeData struct {
	Type         string   `json:"Type"`
	Value        string   `json:"Value"`
	Category     string   `json:"Category"`
	OutOfScope   bool     `json:"OutOfScope"`
	DepthStrict  int      `json:"DepthStrict"`
	DepthRelaxed int      `json:"DepthRelaxed"`
	Subtypes     []string `json:"Subtypes,omitempty"`
}

type EdgeData struct {
	SourceID     string `json:"SourceID"`
	TargetID     string `json:"TargetID"`
	ModuleName   string `json:"ModuleName"`
	FunctionName string `json:"FunctionName"`
	Context      string `json:"Context"`
	RawData      string `json:"RawData,omitempty"`
	CreatedAt    string `json:"CreatedAt"`
}

type ProjectGraph struct {
	ProjectName   string              `json:"ProjectName"`
	InitialTarget string              `json:"InitialTarget"`
	MaxDepth      int                 `json:"MaxDepth"`
	StrictDepth   bool                `json:"StrictDepth"`
	Nodes         map[string]NodeData `json:"Nodes"`
	Edges         []EdgeData          `json:"Edges"`
}

type ProcessorToDispatcherData struct {
	ProjectID  string `json:"ProjectID"`
	ModuleName string `json:"ModuleName"`
	Function   string `json:"Function"`
}

// ===================================================================================
// Module Interfaces and Registrations
// ===================================================================================

// Module defines the interface all reconnaissance plugins must implement.
type Module interface {
	Exec(ModuleInput) (ModuleOutput, error)
	Name() string
	Capabilities() (ModuleCapabilities, error)
}

// FunctionCapabilities defines concurrency and rate limits for a function or module.
type FunctionCapabilities struct {
	Limit        int                    `json:"limit,omitempty"`         // Max concurrent goroutines
	DelayMs      int                    `json:"delay_ms,omitempty"`      // Pause between requests in ms
	InputTypes   []string               `json:"input_types,omitempty"`   // Entity types accepted
	RequiredTags [][]string             `json:"required_tags,omitempty"` // Required entity tags
	Meta         map[string]interface{} `json:"meta,omitempty"`          // Arbitrary metadata
}

// ModuleCapabilities defines what input types and functions a module supports.
type ModuleCapabilities struct {
	Functions  []string `json:"functions,omitempty"`
	InputTypes []string `json:"input_types,omitempty"`

	// Defaults applied to all functions in the module.
	ModuleConfig *FunctionCapabilities `json:"module_config,omitempty"`

	// Per-function configuration; takes precedence over ModuleConfig.
	CustomFunctions map[string]FunctionCapabilities `json:"custom_functions,omitempty"`
}

// ModuleRegistration binds a module name to its resolved capabilities.
type ModuleRegistration struct {
	Name        string
	Caps        ModuleCapabilities
	EnabledFunc map[string]bool
}

type PendingTask struct {
	ModuleName   string
	Function     string
	EntityType   string
	EntityTags   []string
	DepthStrict  int
	DepthRelaxed int
}

// ProjectInfo is a row from the master database projects table.
type ProjectInfo struct {
	ID                 int
	Name               string
	DBIdentifier       string
	InitialTargetType  string
	InitialTargetValue string
	Status             string
	CreatedAt          time.Time
}

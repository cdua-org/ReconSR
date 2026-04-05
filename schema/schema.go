// Package schema defines the core data structures and interfaces
// used across the ReconSR application to ensure consistent data flow.
package schema

import "time"

// ===================================================================================
// Data Transfer Objects (DTOs) for inter-component communication
// ===================================================================================

// Entity defines a basic data unit in the system (e.g., domain, ip).
type Entity struct {
	Type  string `json:"Type,omitempty"`
	Value string `json:"Value"`
}

// ModuleFunction pairs a module name with a specific function.
type ModuleFunction struct {
	ModuleName string `json:"ModuleName"`
	Function   string `json:"Function"`
}

// --- 1. Repository to Dispatcher ---

// RepoToDispatcherBatchItem represents a single entity and its completed functions.
type RepoToDispatcherBatchItem struct {
	Entity             Entity           `json:"Entity"`
	OutOfScope         bool             `json:"OutOfScope"`
	CompletedFunctions []ModuleFunction `json:"CompletedFunctions"`
}

// RepoToDispatcherData is the data structure sent from the Repository to the Dispatcher.
type RepoToDispatcherData struct {
	ProjectID string                      `json:"ProjectID"`
	Batch     []RepoToDispatcherBatchItem `json:"Batch"`
}

// --- 2. Dispatcher to Module ---

// ModuleInput is the data structure sent from the Dispatcher to a Module.
type ModuleInput struct {
	Target    Entity   `json:"Target"`
	Functions []string `json:"Functions"`
}

// --- 3. Module to Dispatcher ---

// ModuleResult represents a single result from a module's execution.
type ModuleResult struct {
	Type       string `json:"Type"`
	Value      string `json:"Value"`
	Context    string `json:"Context"`
	Applied    bool   `json:"Applied,omitempty"`
	OutOfScope bool   `json:"OutOfScope,omitempty"`
}

// ModuleExecution encapsulates the results of a single function's execution.
type ModuleExecution struct {
	Function string         `json:"Function"`
	Results  []ModuleResult `json:"Results"`
	RawData  string         `json:"RawData"`
	Error    *string        `json:"Error"`
}

// ModuleOutput is the data structure sent from a Module to the Dispatcher.
type ModuleOutput struct {
	Executions []ModuleExecution `json:"Executions"`
}

// --- 4. Dispatcher to Processor ---

// DispatcherToProcessorData is the data structure sent from the Dispatcher to the Processor.
type DispatcherToProcessorData struct {
	ProjectID    string            `json:"ProjectID"`
	ModuleName   string            `json:"ModuleName"`
	SourceEntity Entity            `json:"SourceEntity"`
	Executions   []ModuleExecution `json:"Executions"`
}

// --- 5. Input to Processor ---

// ProcessorInputResult mirrors the structure of a standard module result.
type ProcessorInputResult struct {
	Type       string `json:"Type"`
	Value      string `json:"Value"`
	Context    string `json:"Context"`
	Applied    bool   `json:"Applied,omitempty"`
	OutOfScope bool   `json:"OutOfScope,omitempty"`
}

// ProcessorInputExecution wraps the incoming results.
type ProcessorInputExecution struct {
	Function string                 `json:"Function"`
	Results  []ProcessorInputResult `json:"Results"`
	RawData  string                 `json:"RawData,omitempty"`
	Error    *string                `json:"Error,omitempty"`
}

// ProcessorInputError represents an error reported by the system (e.g., dispatcher) before or during module execution.
type ProcessorInputError struct {
	Function string `json:"Function"`
	Type     string `json:"Type"`
	Text     string `json:"Text"`
}

// ProcessorInputData is the generalized data structure sent to the Processor.
type ProcessorInputData struct {
	ProjectID          string                    `json:"ProjectID"`
	ModuleName         string                    `json:"ModuleName"`
	SourceEntity       Entity                    `json:"SourceEntity"`
	Executions         []ProcessorInputExecution `json:"Executions"`
	RequestedFunctions []string                  `json:"RequestedFunctions,omitempty"`
	Errors             []ProcessorInputError     `json:"Errors,omitempty"`
}

// PipelineInjection represents the initial data injected into the processing loop.
type PipelineInjection struct {
	ToProcessor  *ProcessorInputData
	ToDispatcher *RepoToDispatcherData
}

// --- 6. Processor to Repository ---

// ProcessorToRepoValidResult represents a single validated result for storage.
type ProcessorToRepoValidResult struct {
	Function   string `json:"Function"`
	Type       string `json:"Type"`
	Value      string `json:"Value"`
	Context    string `json:"Context"`
	RawData    string `json:"RawData,omitempty"`
	Applied    bool   `json:"Applied,omitempty"`
	OutOfScope bool   `json:"OutOfScope,omitempty"`
}

// ProcessorToRepoError represents a single error finding for storage.
type ProcessorToRepoError struct {
	Function  string `json:"Function"`
	ErrorType string `json:"ErrorType"`
	ErrorText string `json:"ErrorText"`
}

// ProcessorToRepoData is the data structure sent from the Processor to the Repository.
type ProcessorToRepoData struct {
	ProjectID               string                       `json:"ProjectID"`
	ModuleName              string                       `json:"ModuleName"`
	SourceEntity            Entity                       `json:"SourceEntity"`
	ValidResults            []ProcessorToRepoValidResult `json:"ValidResults"`
	FunctionsWithoutResults []string                     `json:"FunctionsWithoutResults"`
	Errors                  []ProcessorToRepoError       `json:"Errors"`
}

// GraphEdge represents a connection between two entities discovered during a scan.
type GraphEdge struct {
	Source           Entity `json:"Source"`
	Target           Entity `json:"Target"`
	TargetOutOfScope bool   `json:"TargetOutOfScope"`
	ModuleName       string `json:"ModuleName"`
	FunctionName     string `json:"FunctionName"`
	Context          string `json:"Context"`
	RawData          string `json:"RawData"`
	CreatedAt        string `json:"CreatedAt"`
}

// ProjectGraph encapsulates all nodes and edges of a project for visualization.
type ProjectGraph struct {
	ProjectName   string      `json:"ProjectName"`
	InitialTarget string      `json:"InitialTarget"`
	Edges         []GraphEdge `json:"Edges"`
}

// ProcessorToDispatcherData is the data structure for reporting invalid data.
type ProcessorToDispatcherData struct {
	ProjectID  string `json:"ProjectID"`
	ModuleName string `json:"ModuleName"`
	Function   string `json:"Function"`
}

// ===================================================================================
// Module Interfaces and Registrations
// ===================================================================================

// Module defines the contract that all reconnaissance plugins must implement.
// Modules must execute concurrently without side effects.
type Module interface {
	Exec(ModuleInput) (ModuleOutput, error)
	Name() string
	Capabilities() (ModuleCapabilities, error)
}

// ModuleCapabilities defines what input types and functions a module supports.
type ModuleCapabilities struct {
	Functions  []string `json:"functions"`
	InputTypes []string `json:"input_types"`
}

// ModuleRegistration associates a module name with its capabilities for repository storage.
type ModuleRegistration struct {
	Name        string
	Caps        ModuleCapabilities
	EnabledFunc map[string]bool
}

// ProjectInfo represents a record in the master database's projects table.
type ProjectInfo struct {
	ID                 int
	Name               string
	DBIdentifier       string
	InitialTargetType  string
	InitialTargetValue string
	Status             string
	CreatedAt          time.Time
}

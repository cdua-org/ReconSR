package controller

import (
	"cdua-org/ReconSR/internal/dispatcher"
	"cdua-org/ReconSR/internal/repository"
	"cdua-org/ReconSR/internal/scopemanager"
	"cdua-org/ReconSR/internal/validator"
	"cdua-org/ReconSR/schema"
	"context"
	"errors"
)

var (
	activeSession *schema.PipelineInjection
	currentProjID string
)

var (
	ErrUnsupportedType = validator.ErrUnsupportedType
	ErrInvalidSyntax   = validator.ErrInvalidSyntax
	ErrOutOfScope      = errors.New("out_of_scope")
	ErrNoModules       = errors.New("no_modules_found")
	ErrNoActiveFuncs   = errors.New("no_active_functions")
)

// GetInjection returns the prepared injection for the pipeline and clears it.
func GetInjection() *schema.PipelineInjection {
	inj := activeSession
	activeSession = nil
	return inj
}

// GetActiveGraph retrieves the results for the currently active session.
func GetActiveGraph(ctx context.Context, includeRawData bool) (*schema.ProjectGraph, error) {
	if currentProjID == "" {
		return nil, errors.New("no active project")
	}
	return repository.GetGraphData(ctx, currentProjID, includeRawData)
}

// GetActiveProjectStats retrieves the counts of unique entity values for the active project.
func GetActiveProjectStats(ctx context.Context) (map[string]int, error) {
	if currentProjID == "" {
		return nil, errors.New("no active project")
	}
	return repository.GetProjectStats(ctx, currentProjID)
}

// SetActiveProject explicitly sets the current project identifier.
func SetActiveProject(projectID string) {
	currentProjID = projectID
}

// GetActiveProjectID returns the current project identifier.
func GetActiveProjectID() string {
	return currentProjID
}

// ClearActiveProject resets the current project identifier.
func ClearActiveProject() {
	currentProjID = ""
	activeSession = nil
}

// ValidateTarget checks if the input is valid and returns its type and value.
func ValidateTarget(targetType, rawInput string) (string, string, error) {
	res, err := validator.Validate(targetType, rawInput)
	if err != nil {
		return "", "", err
	}

	if scopemanager.IsOutOfScope(res.Type, res.Value) {
		return "", "", ErrOutOfScope
	}

	return res.Type, res.Value, nil
}

// GetProjects searches for existing projects and checks module support by target.
func GetProjects(ctx context.Context, targetType, targetValue string) ([]schema.ProjectInfo, bool, bool, error) {
	return repository.FindProjects(ctx, targetType, targetValue)
}

// GetProjectStatus analyzes pending tasks and errors for a specific project.
func GetProjectStatus(ctx context.Context, projectID string) ([]string, []string, error) {
	rawPending, errs, err := repository.GetProjectStatus(ctx, projectID)
	if err != nil {
		return nil, nil, err
	}

	pendingMap := make(map[string]bool)
	for _, task := range rawPending {
		if dispatcher.IsActionable(task.EntityType, task.ModuleName, task.Function, task.EntityTags) {
			pendingMap[task.ModuleName+":"+task.Function] = true
		}
	}

	var pending []string
	for p := range pendingMap {
		pending = append(pending, p)
	}

	return pending, errs, nil
}

// ResetProjectLog clears the execution history to force a rescan.
func ResetProjectLog(ctx context.Context, projectID string, clearAll, clearErrors bool) error {
	return repository.ResetProjectLog(ctx, projectID, clearAll, clearErrors)
}

// CreateNewProject generates a DB and prepares the initial session state.
func CreateNewProject(ctx context.Context, targetType, targetValue string) (string, error) {
	// Double check module availability before final creation
	_, hasModules, hasActiveFuncs, err := repository.FindProjects(ctx, targetType, targetValue)
	if err != nil {
		return "", err
	}
	if !hasModules {
		return "", ErrNoModules
	}
	if !hasActiveFuncs {
		return "", ErrNoActiveFuncs
	}

	routeRef, err := repository.CreateProjectDB(ctx, targetType, targetValue)
	if err != nil {
		return "", err
	}

	if err := SetResumeSession(ctx, routeRef, true, false); err != nil {
		return "", err
	}

	return routeRef, nil
}

// SetResumeSession prepares the payload for an existing project and sets it as active.
func SetResumeSession(ctx context.Context, projectID string, resumePending, retryErrors bool) error {
	settings := GetModuleSettings()
	if err := dispatcher.LoadConfig(ctx, settings); err != nil {
		return err
	}
	payload, err := repository.GetResumePayload(ctx, projectID, resumePending, retryErrors)
	if err != nil {
		return err
	}
	if payload == nil {
		return errors.New("no pending tasks found for project")
	}
	activeSession = &schema.PipelineInjection{ToDispatcher: payload}
	currentProjID = projectID
	return nil
}

// GetSystemStatus returns the current module and function counts from the dispatcher.
func GetSystemStatus(ctx context.Context) (totalMods, activeMods, totalFuncs, activeFuncs int, err error) {
	settings := GetModuleSettings()

	allCaps := dispatcher.GetAllCapabilities()
	totalMods = len(allCaps)
	for _, fns := range allCaps {
		totalFuncs += len(fns)
	}

	for _, fns := range settings {
		hasActive := false
		for _, enabled := range fns {
			if enabled {
				activeFuncs++
				hasActive = true
			}
		}
		if hasActive {
			activeMods++
		}
	}
	return totalMods, activeMods, totalFuncs, activeFuncs, nil
}

// GetProjectGraph retrieves the complete relationship graph for a project.
func GetProjectGraph(ctx context.Context, projectID string, includeRawData bool) (*schema.ProjectGraph, error) {
	return repository.GetGraphData(ctx, projectID, includeRawData)
}

// GetModuleCount returns the total number of registered modules.
func GetModuleCount() int {
	return len(dispatcher.ModuleRegistry)
}

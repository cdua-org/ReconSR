package processor

import (
	"cdua-org/ReconSR/internal/scopemanager"
	"cdua-org/ReconSR/internal/validator"
	"cdua-org/ReconSR/schema"
	"fmt"
	"sync"
)

// Process handles data validation and type correction by routing entities to type-specific handlers.
func Process(data *schema.ProcessorInputData, out chan<- *schema.ProcessorToRepoData, writersWg *sync.WaitGroup) {
	var validResults []schema.ProcessorToRepoValidResult
	var functionsWithoutResults []string
	var errors []schema.ProcessorToRepoError

	// Translate system errors from dispatcher directly
	for _, e := range data.Errors {
		errors = append(errors, schema.ProcessorToRepoError{
			Function:  e.Function,
			ErrorType: e.Type,
			ErrorText: e.Text,
		})
	}

	// Build a lookup map for requested functions if provided (from Dispatcher)
	requestedSet := make(map[string]bool)
	for _, fn := range data.RequestedFunctions {
		requestedSet[fn] = true
	}

	returnedSet := make(map[string]bool)
	functionHasFindings := make(map[string]bool)
	functionHasErrors := make(map[string]bool)
	functionRawData := make(map[string]string)
	var rogueFunctions []string

	// First pass: identify rogue functions
	for _, exec := range data.Executions {
		if len(data.RequestedFunctions) > 0 && !requestedSet[exec.Function] {
			rogueFunctions = append(rogueFunctions, exec.Function)
		}
	}

	// If contract is violated, fail ALL requested functions of this module
	if len(rogueFunctions) > 0 && len(data.RequestedFunctions) > 0 {
		for _, reqFn := range data.RequestedFunctions {
			errors = append(errors, schema.ProcessorToRepoError{
				Function:  reqFn,
				ErrorType: "contract_violation",
				ErrorText: fmt.Sprintf("module %q violated contract: returned unrequested functions %v", data.ModuleName, rogueFunctions),
			})
			returnedSet[reqFn] = true
			functionHasErrors[reqFn] = true
		}
	}

	for _, exec := range data.Executions {
		functionRawData[exec.Function] = exec.RawData

		// Skip if already handled by contract violation logic or if rogue
		if returnedSet[exec.Function] || (len(data.RequestedFunctions) > 0 && !requestedSet[exec.Function]) {
			continue
		}

		returnedSet[exec.Function] = true

		if exec.Error != nil && *exec.Error != "" {
			errors = append(errors, schema.ProcessorToRepoError{
				Function:  exec.Function,
				ErrorType: "function_error",
				ErrorText: *exec.Error,
			})
			functionHasErrors[exec.Function] = true
			continue
		}

		for _, res := range exec.Results {
			// Skip self-discovery
			if res.Value == data.SourceEntity.Value && res.Type == data.SourceEntity.Type {
				continue
			}

			// Check for incomplete data from module
			if (res.Type == "" && res.Value != "") || (res.Type != "" && res.Value == "") {
				errors = append(errors, schema.ProcessorToRepoError{
					Function:  exec.Function,
					ErrorType: "incomplete_data",
					ErrorText: fmt.Sprintf("function %q returned incomplete data: type=%q, value=%q", exec.Function, res.Type, res.Value),
				})
				functionHasErrors[exec.Function] = true
				continue
			}

			vRes, err := validator.Validate(res.Type, res.Value)
			if err != nil {
				errType := "syntax_error"
				errText := fmt.Sprintf("function %q: %s is not a valid %s", exec.Function, res.Value, res.Type)

				if err == validator.ErrUnsupportedType {
					errType = "unsupported_type"
					errText = fmt.Sprintf("function %q returned unsupported entity type: %s", exec.Function, res.Type)
				}

				errors = append(errors, schema.ProcessorToRepoError{
					Function:  exec.Function,
					ErrorType: errType,
					ErrorText: errText,
				})
				functionHasErrors[exec.Function] = true
				continue
			}

			outOfScope := res.OutOfScope
			if !outOfScope {
				outOfScope = scopemanager.IsOutOfScope(vRes.Type, vRes.Value)
			}

			applied := res.Applied
			if applied {
				validTypes := data.FunctionInputTypes[exec.Function]
				typeSupported := false
				for _, t := range validTypes {
					if t == vRes.Type {
						typeSupported = true
						break
					}
				}
				if !typeSupported {
					applied = false
				}
			}

			validResults = append(validResults, schema.ProcessorToRepoValidResult{
				Function:   exec.Function,
				Type:       vRes.Type,
				Value:      vRes.Value,
				Context:    res.Context,
				Applied:    applied,
				OutOfScope: outOfScope,
			})
			functionHasFindings[exec.Function] = true
		}
	}

	for _, reqFn := range data.RequestedFunctions {
		alreadyErrored := false
		for _, e := range errors {
			if e.Function == reqFn {
				alreadyErrored = true
				break
			}
		}
		if alreadyErrored {
			continue
		}

		if !returnedSet[reqFn] {
			errors = append(errors, schema.ProcessorToRepoError{
				Function:  reqFn,
				ErrorType: "missing_function",
				ErrorText: fmt.Sprintf("module %q failed to return results for requested function %q", data.ModuleName, reqFn),
			})
			functionHasErrors[reqFn] = true
		} else if !functionHasFindings[reqFn] && !functionHasErrors[reqFn] {
			functionsWithoutResults = append(functionsWithoutResults, reqFn)
		}
	}

	if len(returnedSet) > 0 || len(errors) > 0 {
		repoData := &schema.ProcessorToRepoData{
			ProjectID:               data.ProjectID,
			ModuleName:              data.ModuleName,
			SourceEntity:            data.SourceEntity,
			ValidResults:            validResults,
			FunctionsWithoutResults: functionsWithoutResults,
			FunctionRawData:         functionRawData,
			Errors:                  errors,
		}

		out <- repoData
		if len(validResults) > 0 {
			writersWg.Add(len(validResults) - 1)
		} else {
			writersWg.Done()
		}
	} else {
		writersWg.Done()
	}
}

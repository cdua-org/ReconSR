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
	var functionsWithoutResults []string
	var errors []schema.ProcessorToRepoError

	returnedSet := make(map[string]bool)
	functionHasFindings := make(map[string]bool)
	functionHasErrors := make(map[string]bool)
	functionRawData := make(map[string]string)

	aggregatedGroups := make(map[schema.EntityRef]map[string]*schema.ProcessorToRepoValidResult)

	refs := make(map[string]*schema.EntityRef)
	getRef := func(t, v string) *schema.EntityRef {
		k := t + ":" + v
		if r, ok := refs[k]; ok {
			return r
		}
		r := &schema.EntityRef{Type: t, Value: v}
		refs[k] = r
		return r
	}

	// Translate system errors from dispatcher directly
	for _, e := range data.Errors {
		errors = append(errors, schema.ProcessorToRepoError{
			Function:  e.Function,
			ErrorType: e.Type,
			ErrorText: e.Text,
		})
		functionHasErrors[e.Function] = true
	}

	// Build a lookup map for requested functions if provided (from Dispatcher)
	requestedSet := make(map[string]bool)
	for _, fn := range data.RequestedFunctions {
		requestedSet[fn] = true
	}

	var rogueFunctions []string
	for _, exec := range data.Executions {
		if len(data.RequestedFunctions) > 0 && !requestedSet[exec.Function] {
			rogueFunctions = append(rogueFunctions, exec.Function)
		}
	}

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

	sourceKey := data.SourceEntity.Type + ":" + data.SourceEntity.Value
	getRef(data.SourceEntity.Type, data.SourceEntity.Value)
	adj := make(map[string][]string)

	for i := range data.Executions {
		exec := &data.Executions[i]
		if returnedSet[exec.Function] || (len(data.RequestedFunctions) > 0 && !requestedSet[exec.Function]) {
			continue
		}
		if exec.Error != nil && *exec.Error != "" {
			continue
		}
		for j := range exec.Results {
			res := &exec.Results[j]
			if res.Source == nil {
				res.Source = getRef(data.SourceEntity.Type, data.SourceEntity.Value)
			} else {
				res.Source = getRef(res.Source.Type, res.Source.Value)
			}
			targetRef := getRef(res.Type, res.Value)

			srcKey := res.Source.Type + ":" + res.Source.Value
			targetKey := targetRef.Type + ":" + targetRef.Value
			adj[srcKey] = append(adj[srcKey], targetKey)
		}
	}

	reachable := make(map[string]bool)
	reachable[sourceKey] = true
	queue := []string{sourceKey}
	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]
		for _, next := range adj[curr] {
			if !reachable[next] {
				reachable[next] = true
				queue = append(queue, next)
			}
		}
	}

	for key, ref := range refs {
		if !reachable[key] {
			ref.Type = "invalid"
		} else {
			vRes, err := validator.Validate(ref.Type, ref.Value)
			if err != nil {
				ref.Type = "invalid"
			} else {
				ref.Type = vRes.Type
				ref.Value = vRes.Value
			}
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
			// Validate tags
			validTags := make([]string, 0, len(res.Tags))
			tagError := false
			for _, t := range res.Tags {
				if err := validator.ValidateTag(t); err != nil {
					errors = append(errors, schema.ProcessorToRepoError{
						Function:  exec.Function,
						ErrorType: "invalid_tag_format",
						ErrorText: fmt.Sprintf("function %q returned invalid tag %q: tags must contain only [a-z0-9_-]", exec.Function, t),
					})
					functionHasErrors[exec.Function] = true
					tagError = true
					break
				}
				validTags = append(validTags, t)
			}
			if tagError {
				continue
			}

			origTargetKey := res.Type + ":" + res.Value
			targetRef := refs[origTargetKey]
			srcRefVal := *res.Source

			// Skip self-discovery unless new tags are provided to enrich the immediate source entity
			if targetRef.Value == srcRefVal.Value && targetRef.Type == srcRefVal.Type && len(validTags) == 0 {
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

			applied := res.Applied
			if applied {
				validTypes := data.FunctionInputTypes[exec.Function]
				typeSupported := false
				for _, t := range validTypes {
					if t == targetRef.Type {
						typeSupported = true
						break
					}
				}
				if !typeSupported {
					applied = false
				}
			}

			resKey := targetRef.Type + ":" + targetRef.Value
			if aggregatedGroups[srcRefVal] == nil {
				aggregatedGroups[srcRefVal] = make(map[string]*schema.ProcessorToRepoValidResult)
			}

			if existing, found := aggregatedGroups[srcRefVal][resKey]; found {
				for _, nt := range validTags {
					tagFound := false
					for _, et := range existing.Tags {
						if et == nt {
							tagFound = true
							break
						}
					}
					if !tagFound {
						existing.Tags = append(existing.Tags, nt)
					}
				}
				existing.Applied = existing.Applied || applied
				existing.OutOfScope = existing.OutOfScope || res.OutOfScope
			} else {
				cat := res.Category
				if cat == "" {
					cat = "node"
				}
				aggregatedGroups[srcRefVal][resKey] = &schema.ProcessorToRepoValidResult{
					Function:   exec.Function,
					Type:       targetRef.Type,
					Value:      targetRef.Value,
					Context:    res.Context,
					Category:   cat,
					Applied:    applied,
					OutOfScope: res.OutOfScope || scopemanager.IsOutOfScope(targetRef.Type, targetRef.Value),
					Tags:       validTags,
				}
			}
			functionHasFindings[exec.Function] = true
		}
	}

	for _, reqFn := range data.RequestedFunctions {
		if functionHasErrors[reqFn] {
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
		var groups []schema.ResultGroup
		totalResults := 0
		for srcRef, targetMap := range aggregatedGroups {
			var results []schema.ProcessorToRepoValidResult
			for _, v := range targetMap {
				results = append(results, *v)
			}
			groups = append(groups, schema.ResultGroup{
				Source:  srcRef,
				Results: results,
			})
			totalResults += len(results)
		}

		repoData := &schema.ProcessorToRepoData{
			ProjectID:               data.ProjectID,
			ModuleName:              data.ModuleName,
			SourceEntity:            data.SourceEntity,
			Groups:                  groups,
			FunctionsWithoutResults: functionsWithoutResults,
			FunctionRawData:         functionRawData,
			Errors:                  errors,
		}

		out <- repoData
		if totalResults > 0 {
			writersWg.Add(totalResults - 1)
		} else {
			writersWg.Done()
		}
	} else {
		writersWg.Done()
	}
}

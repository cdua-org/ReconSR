package cli

import (
	"slices"
	"strings"
)

type cliArgs struct {
	ShowHelp    bool
	ListModules bool
	ListFuncMod string
	IgnoreScope bool
	Target      string
	ModuleSpecs []string
}

func parseCLIArgs(args []string) cliArgs {
	var parsed cliArgs
	if len(args) <= 1 {
		return parsed
	}

	rawArgs := args[1:]
	positional := make([]string, 0, len(rawArgs))
	flagModules := make([]string, 0, len(rawArgs))

	for i := 0; i < len(rawArgs); i++ {
		arg := rawArgs[i]
		switch {
		case arg == "-h" || arg == "--help":
			parsed.ShowHelp = true
		case arg == "-l" || arg == "--list-modules":
			parsed.ListModules = true
		case arg == "--list-funcs":
			if i+1 < len(rawArgs) && !strings.HasPrefix(rawArgs[i+1], "-") && strings.TrimSpace(rawArgs[i+1]) != "" {
				parsed.ListFuncMod = strings.TrimSpace(rawArgs[i+1])
				i++
			} else {
				parsed.ShowHelp = true
			}
		case strings.HasPrefix(arg, "--list-funcs="):
			val := strings.TrimSpace(strings.TrimPrefix(arg, "--list-funcs="))
			if val == "" {
				parsed.ShowHelp = true
			} else {
				parsed.ListFuncMod = val
			}
		case arg == "-m" || arg == "--module" || arg == "--modules":
			if i+1 < len(rawArgs) && !strings.HasPrefix(rawArgs[i+1], "-") {
				mods := splitModules(rawArgs[i+1])
				if len(mods) == 0 {
					parsed.ShowHelp = true
				} else {
					flagModules = append(flagModules, mods...)
				}
				i++
			} else {
				parsed.ShowHelp = true
			}
		case strings.HasPrefix(arg, "-m="), strings.HasPrefix(arg, "--module="), strings.HasPrefix(arg, "--modules="):
			val := arg[strings.IndexByte(arg, '=')+1:]
			mods := splitModules(val)
			if len(mods) == 0 {
				parsed.ShowHelp = true
			} else {
				flagModules = append(flagModules, mods...)
			}
		case arg == "--ignore-scope":
			parsed.IgnoreScope = true
		case strings.HasPrefix(arg, "-"):
			parsed.ShowHelp = true
		default:
			positional = append(positional, arg)
		}
	}

	if len(positional) > 0 {
		parsed.Target = strings.TrimSpace(positional[0])
		parsed.ModuleSpecs = append(parsed.ModuleSpecs, positional[1:]...)
	}
	parsed.ModuleSpecs = append(parsed.ModuleSpecs, flagModules...)

	if (parsed.IgnoreScope && len(parsed.ModuleSpecs) == 0) || (len(parsed.ModuleSpecs) > 0 && parsed.Target == "") {
		parsed.ShowHelp = true
	}

	return parsed
}

func splitModules(val string) []string {
	fields := strings.FieldsFunc(val, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t'
	})
	res := make([]string, 0, len(fields))
	for _, part := range fields {
		part = strings.TrimSpace(part)
		if part != "" {
			res = append(res, part)
		}
	}
	return res
}

func parseModuleSpecs(specs []string) map[string][]string {
	requested := make(map[string][]string, len(specs))
	for _, spec := range specs {
		spec = strings.TrimSpace(spec)
		if spec == "" {
			continue
		}
		if strings.Contains(spec, ":") {
			parts := strings.Split(spec, ":")
			modName := strings.TrimSpace(parts[0])
			if modName == "" {
				continue
			}
			existing, exists := requested[modName]
			if exists && existing == nil {
				continue
			}
			hasFuncs := false
			for _, p := range parts[1:] {
				fn := strings.TrimSpace(p)
				if fn != "" {
					hasFuncs = true
					if !slices.Contains(requested[modName], fn) {
						requested[modName] = append(requested[modName], fn)
					}
				}
			}
			if !hasFuncs && !exists {
				requested[modName] = nil
			}
		} else {
			requested[spec] = nil
		}
	}
	return requested
}

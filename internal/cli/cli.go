package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"cdua-org/ReconSR/internal/cli/spinner"
	"cdua-org/ReconSR/internal/controller"
	"cdua-org/ReconSR/internal/i18n"
	"cdua-org/ReconSR/internal/report"
)

// Application metadata variables. Can be overridden at build time via ldflags.
// Example: go build -ldflags "-X 'cdua-org/ReconSR/internal/cli.AppVersion=v1.0.0'"
var (
	AppName    = "ReconSR"
	AppVersion = "dev"
	AppDesc    = "Automated OSINT tool"
	AppStage   = "Initial design and development phase"
)

// WikiURL is the link to the project documentation and setup guides.
const WikiURL = "https://github.com/cdua-org/ReconSR/wiki"

// ShowResultsMenu presents visualization options.
func ShowResultsMenu(ctx context.Context) {
	for {
		fmt.Println("\n" + colorCyan + colorBold + "--- " + i18n.T["OPT_SHOW_RESULTS"] + " ---" + colorReset)
		fmt.Println("1. " + i18n.T["OPT_TREE_CONSOLE"])
		fmt.Println("2. " + i18n.T["OPT_TREE_HTML"])
		fmt.Println("3. " + i18n.T["OPT_GRAPH_HTML"])
		fmt.Println("4. " + i18n.T["OPT_BACK"])
		fmt.Println("5. " + i18n.T["OPT_EXIT"])
		fmt.Print("\n" + colorGreen + i18n.T["LBL_CHOICE_PROMPT"] + ": " + colorReset)

		choice := readUserInput()
		fmt.Println("--------------------------------------------------")

		switch choice {
		case "1":
			graph, err := controller.GetActiveGraph(ctx, false)
			if err != nil {
				fmt.Printf("%s: %v\n", i18n.T["LBL_ERROR"], err)
				continue
			}
			report.RenderResultsTree(os.Stdout, graph, &report.ConsoleTreeFormatter{})
		case "2":
			stopSpinner := spinner.Start(ctx, i18n.T["OPT_TREE_HTML"], nil, 0)
			graph, err := controller.GetActiveGraph(ctx, false)
			if err != nil {
				stopSpinner()
				fmt.Printf("%s: %v\n", i18n.T["LBL_ERROR"], err)
				continue
			}
			filename, err := report.GenerateTreeHTML(graph)
			stopSpinner()
			if err != nil {
				fmt.Printf("%s: %v\n", i18n.T["LBL_ERROR"], err)
			} else {
				fmt.Printf("\n%s: %s\n", i18n.T["MSG_REPORT_SAVED"], filename)
			}
		case "3":
			graph, err := controller.GetActiveGraph(ctx, true)
			if err != nil {
				fmt.Printf("%s: %v\n", i18n.T["LBL_ERROR"], err)
				continue
			}

			if len(graph.Nodes) >= 5000 {
				fmt.Println(colorYellow + i18n.T["MSG_LARGE_GRAPH_WARNING"] + colorReset)
			}

			stopSpinner := spinner.Start(ctx, i18n.T["MSG_GENERATING_GRAPH"], nil, 0)
			filename, err := report.GenerateHTML(ctx, graph)
			stopSpinner()

			if err != nil {
				fmt.Printf("%s: %v\n", i18n.T["LBL_ERROR"], err)
			} else {
				fmt.Printf("\n%s: %s\n", i18n.T["MSG_REPORT_SAVED"], filename)
			}
		case "4":
			return
		case "5":
			os.Exit(0)
		default:
			fmt.Println(colorRed + i18n.T["ERR_INVALID_CHOICE"] + colorReset)
		}
	}
}

// ShowBanner prints the application banner.
func ShowBanner(ctx context.Context) {
	const colorGold = "\033[38;2;204;135;4m"
	logo := `
  ░█▀█░█▀▀░█▀▀░█▀█░█▄░█░█▀▀░█▀█
  ░█▀▄░█▀▀░█░░░█░█░█░▀█░▀▀█░█▀▄
  ░▀░▀░▀▀▀░▀▀▀░▀▀▀░▀░░▀░▀▀▀░▀░▀`

	fmt.Println(colorGold + colorBold + logo + colorReset)
	fmt.Println()
	fmt.Printf(colorCyan+"  :: %s %s ::"+colorReset+"\n", AppName, AppVersion)
	fmt.Printf(colorCyan+"  :: %s ::"+colorReset+"\n", AppDesc)
	fmt.Printf(colorCyan+"  :: %s ::"+colorReset+"\n", AppStage)

	if AppVersion != "dev" {
		release, err := controller.CheckAppUpdate(ctx)
		if err == nil && release != nil && release.TagName != "" && release.TagName != AppVersion {
			fmt.Println()
			fmt.Printf(colorYellow+colorBold+"  [!] %s: %s (current: %s)"+colorReset+"\n", i18n.T["MSG_NEW_VERSION"], release.TagName, AppVersion)
			fmt.Printf(colorYellow+"      %s: reconsr update"+colorReset+"\n", i18n.T["MSG_RUN_COMMAND"])
		}
	}
	fmt.Println()

	fmt.Println(colorCyan + colorBold + "[ " + i18n.T["LBL_SYS_INFO"] + " ]" + colorReset)

	fmt.Printf("  + %-20s %s\n", i18n.T["MSG_INIT_CORE"]+":", colorGreen+i18n.T["MSG_STATUS_READY"]+colorReset)

	totalMods, _, totalFuncs, _, err := controller.GetSystemStatus(ctx)
	if err != nil {
		fmt.Printf("%s: %v\n", i18n.T["LBL_ERROR"], err)
		return
	}
	fmt.Printf("  + %-20s %d\n", i18n.T["LBL_MODS"]+":", totalMods)
	fmt.Printf("  + %-20s %d\n", i18n.T["LBL_FUNCS"]+":", totalFuncs)

	fmt.Printf("  + %-20s %s\n", i18n.T["MSG_CONN_DB"]+":", colorGreen+i18n.T["MSG_STATUS_CONN"]+colorReset)
	fmt.Println()
	fmt.Println(colorYellow + "  [!] " + i18n.T["MSG_API_KEYS_NOTE"] + colorReset)
	fmt.Println(colorYellow + "      " + i18n.T["MSG_EMPTY_RESULTS_NOTE"] + colorReset)
	fmt.Println(colorYellow + "      " + i18n.T["MSG_API_KEYS_SETUP"] + ": " + WikiURL + colorReset)
	fmt.Println(colorCyan + "--------------------------------------------------" + colorReset)
}

func printProjectStats(ctx context.Context) {
	if projectID := controller.GetActiveProjectID(); projectID != "" {
		totalEntities, statsByCat, totalsByCat, err := controller.GetActiveProjectStats(ctx)
		if err != nil {
			fmt.Printf("%s: %v\n", i18n.T["LBL_ERROR"], err)
			return
		}
		if len(statsByCat) > 0 {
			fmt.Printf(colorCyan+"Total entities: %d"+colorReset+"\n", totalEntities)

			catKeys := make([]string, 0, len(statsByCat))
			for cat := range statsByCat {
				catKeys = append(catKeys, cat)
			}
			sort.Strings(catKeys)

			for _, cat := range catKeys {
				catTotal := totalsByCat[cat]
				stats := statsByCat[cat]
				if len(stats) == 0 {
					continue
				}

				keys := make([]string, 0, len(stats))
				hasInvalid := false
				for t := range stats {
					if t == "invalid" {
						hasInvalid = true
					} else {
						keys = append(keys, t)
					}
				}
				sort.Strings(keys)
				if hasInvalid {
					keys = append(keys, "invalid")
				}

				displayCat := strings.ToUpper(cat)
				fmt.Printf("\n"+colorCyan+"%s: %d"+colorReset+"\n", displayCat, catTotal)
				for _, t := range keys {
					fmt.Printf("  - %s: %d\n", t, stats[t])
				}
			}
		}
	}
}

// ShowReconCompleteBanner prints the post-scan status message and entity statistics.
func ShowReconCompleteBanner(ctx context.Context) {
	fmt.Println("\n" + colorGreen + colorBold + "--------------------------------------------------" + colorReset)
	fmt.Println(colorGreen + colorBold + "[*] " + i18n.T["MSG_RECON_COMPLETE"] + colorReset)
	printProjectStats(ctx)
	fmt.Println(colorGreen + colorBold + "--------------------------------------------------" + colorReset)
}

// GetRawTarget extracts the target from args or presents a menu of existing targets when no target argument is provided.
func GetRawTarget(ctx context.Context, osArgs []string) string {
	if len(osArgs) >= 2 {
		return osArgs[1]
	}

	targets, err := controller.GetExistingTargets(ctx)
	if err != nil {
		fmt.Printf("%s%s: %v%s\n", colorRed, i18n.T["LBL_ERROR"], err, colorReset)
		targets = nil
	}

	for {
		fmt.Println("\n" + colorCyan + colorBold + "--- " + i18n.T["LBL_TARGET"] + " ---" + colorReset)
		fmt.Println("1. " + i18n.T["OPT_NEW_PROJECT"])

		for i, t := range targets {
			fmt.Printf("%d. %s\n", i+2, t.Value)
		}

		exitIdx := len(targets) + 2
		fmt.Printf("%d. %s\n", exitIdx, i18n.T["OPT_EXIT"])
		fmt.Printf("\n%s%s: %s", colorGreen, i18n.T["LBL_CHOICE_PROMPT"], colorReset)

		choice := readUserInput()
		fmt.Println("--------------------------------------------------")

		idx, err := strconv.Atoi(strings.TrimSpace(choice))
		if err != nil {
			fmt.Println(colorRed + i18n.T["ERR_INVALID_CHOICE"] + colorReset)
			continue
		}

		switch {
		case idx == 1:
			fmt.Printf("\n%s%s %s", colorGreen, i18n.T["LBL_INPUT_TARGET_PROMPT"]+":", colorReset)
			target := strings.TrimSpace(readUserInput())
			if target == "" {
				fmt.Println(colorRed + i18n.T["ERR_INVALID_FORMAT"] + colorReset)
				continue
			}
			_, _, vErr := controller.ValidateTarget(ctx, "auto", target)
			if vErr != nil {
				printTargetError(vErr)
				continue
			}
			return target
		case idx >= 2 && idx <= len(targets)+1:
			return targets[idx-2].Value
		case idx == exitIdx:
			os.Exit(0)
		default:
			fmt.Println(colorRed + i18n.T["ERR_INVALID_CHOICE"] + colorReset)
		}
	}
}

func resolveTarget(ctx context.Context, rawInput string) (string, string, error) {
	existingTargets, err := controller.GetExistingTargets(ctx)
	if err == nil {
		for _, item := range existingTargets {
			if item.Value == rawInput {
				return item.Type, item.Value, nil
			}
		}
	}
	return controller.ValidateTarget(ctx, "auto", rawInput)
}

// HandleUserInput manages the UI loop for projects and actions.
func HandleUserInput(ctx context.Context, rawInput string) bool {
	if rawInput == "" {
		return false
	}

	var targetType, targetValue string

	for {
		if projectID := controller.GetActiveProjectID(); projectID != "" {
			if targetValue == "" {
				if graph, gErr := controller.GetActiveGraph(ctx, false); gErr == nil && graph != nil && graph.InitialTarget != "" {
					if tType, tVal, rErr := resolveTarget(ctx, graph.InitialTarget); rErr == nil {
						targetType = tType
						targetValue = tVal
						rawInput = tVal
					}
				}
			}
			run, stop := handleProjectActions(ctx, projectID, targetType, targetValue)
			if stop {
				return false
			}
			if run {
				printReconStatus(false)
				return true
			}
			controller.ClearActiveProject()
			rawInput = targetValue
			continue
		}

		var err error
		targetType, targetValue, err = resolveTarget(ctx, rawInput)
		if err != nil {
			printTargetError(err)
			return false
		}

		fmt.Printf("\n%s%s: %s%s%s%s (%s)\n", colorCyan, i18n.T["LBL_TARGET"], colorReset, colorBold, targetValue, colorReset, targetType)

		tM, aM, tF, aF, err := controller.GetSystemStatus(ctx)
		if err != nil {
			fmt.Printf("%s%s: %v%s\n", colorRed, i18n.T["LBL_ERROR"], err, colorReset)
			continue
		}
		fmt.Printf("%s%s:%s %d/%d %s, %d/%d %s\n", colorCyan, i18n.T["MSG_ACTIVE_TOOLS"], colorReset, aM, tM, i18n.T["LBL_MODS"], aF, tF, i18n.T["LBL_FUNCS"])
		projects, hasModules, hasActiveFuncs, err := controller.GetProjects(ctx, targetType, targetValue)
		if err != nil {
			fmt.Printf("%s%s: %v%s\n", colorRed, i18n.T["LBL_ERROR"], err, colorReset)
			return false
		}

		if !hasModules {
			fmt.Println(colorRed + i18n.T["ERR_NO_MODULES"] + ": '" + targetType + "'" + colorReset)
			os.Exit(0)
		}

		if !hasActiveFuncs && len(projects) == 0 {
			fmt.Println(colorRed + i18n.T["ERR_NO_ACTIVE_FUNCS"] + colorReset)
			fmt.Println("\n" + colorYellow + "[!] " + i18n.T["MSG_CONFIG_INFO"] + colorReset)

			fmt.Printf("\n1. %s\n", i18n.T["OPT_BACK"])
			fmt.Printf("2. %s\n", i18n.T["OPT_EXIT"])
			fmt.Printf("\n%s%s: %s", colorGreen, i18n.T["LBL_CHOICE_PROMPT"], colorReset)

			choice := readUserInput()
			fmt.Println("--------------------------------------------------")

			if choice == "0" {
				handleModuleConfiguration(ctx)
				continue
			}

			idx, err := strconv.Atoi(strings.TrimSpace(choice))
			if err != nil {
				fmt.Println(colorRed + i18n.T["ERR_INVALID_CHOICE"] + colorReset)
				continue
			}

			switch idx {
			case 1:
				rawInput = GetRawTarget(ctx, []string{os.Args[0]})
				if rawInput == "" {
					return false
				}
				continue
			case 2:
				return false
			default:
				fmt.Println(colorRed + i18n.T["ERR_INVALID_CHOICE"] + colorReset)
				continue
			}
		}

		fmt.Println("\n" + colorYellow + "[!] " + i18n.T["MSG_CONFIG_INFO"] + colorReset)

		fmt.Println("\n" + colorCyan + colorBold + "--- " + i18n.T["MSG_PROJECTS_EXIST_2"] + " ---" + colorReset)
		if !hasActiveFuncs {
			fmt.Printf("1. %s %s(%s)%s\n", i18n.T["OPT_NEW_PROJECT"], colorRed, i18n.T["ERR_NO_ACTIVE_FUNCS"], colorReset)
		} else {
			fmt.Printf("1. %s\n", i18n.T["OPT_NEW_PROJECT"])
		}

		for i, p := range projects {
			fmt.Printf("%d. %s %s (%s: %s, %s: %s)\n", i+2, i18n.T["OPT_CONTINUE_PROJECT"], p.Name, i18n.T["LBL_CREATED"], p.CreatedAt.Format("2006-01-02 15:04:05"), i18n.T["LBL_SIZE"], formatBytes(p.SizeBytes))
		}

		backIdx := len(projects) + 2
		exitIdx := len(projects) + 3
		fmt.Printf("%d. %s\n", backIdx, i18n.T["OPT_BACK"])
		fmt.Printf("%d. %s\n", exitIdx, i18n.T["OPT_EXIT"])
		fmt.Printf("\n%s%s: %s", colorGreen, i18n.T["LBL_CHOICE_PROMPT"], colorReset)

		choice := readUserInput()
		fmt.Println("--------------------------------------------------")

		if choice == "0" {
			handleModuleConfiguration(ctx)
			continue
		}

		idx, err := strconv.Atoi(strings.TrimSpace(choice))
		if err != nil {
			fmt.Println(colorRed + i18n.T["ERR_INVALID_CHOICE"] + colorReset)
			continue
		}

		switch {
		case idx == backIdx:
			rawInput = GetRawTarget(ctx, []string{os.Args[0]})
			if rawInput == "" {
				return false
			}
			continue
		case idx == exitIdx:
			os.Exit(0)
		case idx == 1:
			if !hasActiveFuncs {
				fmt.Println(colorRed + i18n.T["ERR_INVALID_CHOICE"] + colorReset)
				continue
			}
			if !checkTargetScope(ctx, targetType, targetValue) {
				continue
			}
			newID, err := controller.CreateNewProject(ctx, targetType, targetValue)
			if err != nil {
				fmt.Printf("%s: %v\n", i18n.T["LBL_ERROR"], err)
				continue
			}
			controller.SetActiveProject(newID)
			rawInput = targetValue
			printReconStatus(false)
			return true
		case idx >= 2 && idx <= len(projects)+1:
			controller.SetActiveProject(projects[idx-2].DBIdentifier)
			rawInput = projects[idx-2].InitialTargetValue
		default:
			fmt.Println(colorRed + i18n.T["ERR_INVALID_CHOICE"] + colorReset)
		}
	}
}

func handleModuleConfiguration(ctx context.Context) {
	settings := controller.GetModuleSettings()

	type menuAction struct {
		actionType string
		modName    string
		fnName     string
	}

	for {
		var actions []menuAction
		mods := make([]string, 0, len(settings))
		for m := range settings {
			mods = append(mods, m)
		}
		sort.Strings(mods)

		actions = append(actions, menuAction{actionType: "toggleAll"})

		for _, m := range mods {
			actions = append(actions, menuAction{actionType: "toggleModule", modName: m})

			fns := settings[m]
			fnNames := make([]string, 0, len(fns))
			for f := range fns {
				fnNames = append(fnNames, f)
			}
			sort.Strings(fnNames)
			for _, f := range fnNames {
				actions = append(actions, menuAction{actionType: "toggleFunc", modName: m, fnName: f})
			}
		}

		fmt.Println("\n" + colorCyan + colorBold + "--- " + i18n.T["LBL_CONFIG_TITLE"] + " ---" + colorReset)

		for i, item := range actions {
			idx := i + 1
			switch item.actionType {
			case "toggleAll":
				fmt.Printf("%d. %s[ %s ]%s\n", idx, colorCyan, i18n.T["OPT_TOGGLE_ALL"], colorReset)
			case "toggleModule":
				fmt.Printf("\n%d. %s[ %s ]%s\n", idx, colorCyan, item.modName, colorReset)
			case "toggleFunc":
				status := "[ ]"
				color := colorRed
				if settings[item.modName][item.fnName] {
					status = "[X]"
					color = colorGreen
				}
				fmt.Printf("   %d. %s%s%s %s\n", idx, color, status, colorReset, item.fnName)
			}
		}

		fmt.Printf("\n0. %s[ %s ]%s\n", colorGreen, i18n.T["OPT_SAVE_EXIT"], colorReset)

		fmt.Printf("\n%s%s: %s", colorGreen, i18n.T["LBL_CHOICE_PROMPT"], colorReset)
		choice := readUserInput()

		idx, err := strconv.Atoi(strings.TrimSpace(choice))
		if err != nil {
			continue
		}

		if idx == 0 {
			if err := controller.UpdateModuleSettings(ctx, settings); err != nil {
				fmt.Printf("%s%s: %v%s\n", colorRed, i18n.T["LBL_ERROR"], err, colorReset)
			} else {
				fmt.Println(colorGreen + i18n.T["MSG_CONFIG_SAVED"] + colorReset)
			}
			return
		}

		if idx > 0 && idx <= len(actions) {
			target := actions[idx-1]
			switch target.actionType {
			case "toggleAll":
				allEnabled := true
				for _, fns := range settings {
					for _, enabled := range fns {
						if !enabled {
							allEnabled = false
						}
					}
				}
				newState := !allEnabled
				for m, fns := range settings {
					for f := range fns {
						settings[m][f] = newState
					}
				}
			case "toggleModule":
				allEnabled := true
				for _, enabled := range settings[target.modName] {
					if !enabled {
						allEnabled = false
						break
					}
				}
				newState := !allEnabled
				for f := range settings[target.modName] {
					settings[target.modName][f] = newState
				}
			case "toggleFunc":
				settings[target.modName][target.fnName] = !settings[target.modName][target.fnName]
			}
		}
	}
}

func printTargetError(err error) {
	if err == nil {
		return
	}
	switch {
	case errors.Is(err, controller.ErrOutOfScope):
		fmt.Println(colorRed + i18n.T["ERR_OUT_OF_SCOPE"] + colorReset)
	case errors.Is(err, controller.ErrUnsupportedType):
		fmt.Println(colorRed + i18n.T["ERR_UNSUPPORTED_TYPE"] + colorReset)
	default:
		fmt.Println(colorRed + i18n.T["ERR_INVALID_FORMAT"] + colorReset)
	}
}

func checkTargetScope(ctx context.Context, targetType, targetValue string) bool {
	_, _, err := controller.ValidateTarget(ctx, targetType, targetValue)
	if err != nil {
		printTargetError(err)
		return false
	}
	return true
}

func handleProjectActions(ctx context.Context, projectID, targetType, targetValue string) (run bool, stop bool) {
	for {
		pending, errs, err := controller.GetProjectStatus(ctx, projectID)
		if err != nil {
			fmt.Printf("%s%s: %v%s\n", colorRed, i18n.T["LBL_ERROR"], err, colorReset)
			return false, false
		}

		fmt.Println("\n" + colorCyan + colorBold + "--- " + i18n.T["LBL_PROJECT_STATUS"] + " ---" + colorReset)
		if len(pending) == 0 && len(errs) == 0 {
			fmt.Println(colorGreen + colorBold + "[+] " + i18n.T["MSG_PROJ_COMPLETE"] + colorReset)
		} else {
			if len(pending) > 0 {
				fmt.Printf("%s[%s]%s\n", colorYellow, i18n.T["MSG_PENDING_FOUND"], colorReset)
				for _, p := range pending {
					fmt.Println(colorYellow + "  - " + p + colorReset)
				}
			}
			if len(errs) > 0 {
				fmt.Printf("%s[%s]%s\n", colorRed, i18n.T["MSG_ERRORS_FOUND"], colorReset)
				for _, e := range errs {
					fmt.Println(colorRed + "  - " + e + colorReset)
				}
			}
		}

		fmt.Println("\n" + colorYellow + "[!] " + i18n.T["MSG_CONFIG_INFO"] + colorReset)

		fmt.Println("\n" + colorCyan + colorBold + "--- " + i18n.T["MSG_PROJ_ACTION"] + " ---" + colorReset)
		fmt.Printf("1. %s\n", i18n.T["OPT_FULL_RESCAN"])
		optIdx := 2
		var contOpt, retryOpt, resOpt, backOpt, deleteOpt, exitOpt int

		if len(pending) > 0 {
			contOpt = optIdx
			fmt.Printf("%d. %s\n", optIdx, i18n.T["OPT_CONTINUE_PENDING"])
			optIdx++
		}
		if len(errs) > 0 {
			retryOpt = optIdx
			fmt.Printf("%d. %s\n", optIdx, i18n.T["OPT_RETRY_ERRORS"])
			optIdx++
		}

		resOpt = optIdx
		fmt.Printf("%d. %s\n", optIdx, i18n.T["OPT_SHOW_RESULTS"])
		optIdx++

		deleteOpt = optIdx
		fmt.Printf("%d. %s\n", optIdx, i18n.T["OPT_DELETE_PROJECT"])
		optIdx++

		backOpt = optIdx
		fmt.Printf("%d. %s\n", optIdx, i18n.T["OPT_BACK"])
		optIdx++

		exitOpt = optIdx
		fmt.Printf("%d. %s\n", optIdx, i18n.T["OPT_EXIT"])

		fmt.Printf("\n%s%s: %s", colorGreen, i18n.T["LBL_CHOICE_PROMPT"], colorReset)
		choice := readUserInput()
		fmt.Println("--------------------------------------------------")

		if choice == "0" {
			handleModuleConfiguration(ctx)
			continue
		}

		idx, err := strconv.Atoi(strings.TrimSpace(choice))
		if err != nil {
			fmt.Println(colorRed + i18n.T["ERR_INVALID_CHOICE"] + colorReset)
			continue
		}

		switch {
		case idx == 1:
			if !checkTargetScope(ctx, targetType, targetValue) {
				continue
			}
			if err := controller.ResetProjectLog(ctx, projectID, true, false); err != nil {
				fmt.Printf("%s%s: %v%s\n", colorRed, i18n.T["LBL_ERROR"], err, colorReset)
				continue
			}
			if err := controller.SetResumeSession(ctx, projectID, true, false); err != nil {
				fmt.Printf("%s%s: %v%s\n", colorRed, i18n.T["LBL_ERROR"], err, colorReset)
				continue
			}
			return true, false
		case contOpt > 0 && idx == contOpt:
			if !checkTargetScope(ctx, targetType, targetValue) {
				continue
			}
			if err := controller.SetResumeSession(ctx, projectID, true, false); err != nil {
				fmt.Printf("%s%s: %v%s\n", colorRed, i18n.T["LBL_ERROR"], err, colorReset)
				continue
			}
			return true, false
		case retryOpt > 0 && idx == retryOpt:
			if !checkTargetScope(ctx, targetType, targetValue) {
				continue
			}
			if err := controller.SetResumeSession(ctx, projectID, false, true); err != nil {
				fmt.Printf("%s%s: %v%s\n", colorRed, i18n.T["LBL_ERROR"], err, colorReset)
				continue
			}
			return true, false
		case idx == resOpt:
			ShowResultsMenu(ctx)
			continue
		case idx == deleteOpt:
			deleted, stopApp := handleDeleteProject(ctx, projectID)
			if stopApp {
				return false, true
			}
			if deleted {
				return false, false
			}
			continue
		case idx == backOpt:
			return false, false
		case idx == exitOpt:
			return false, true
		default:
			fmt.Println(colorRed + i18n.T["ERR_INVALID_CHOICE"] + colorReset)
		}
	}
}

func handleDeleteProject(ctx context.Context, projectID string) (bool, bool) {
	for {
		fmt.Println("\n" + colorCyan + colorBold + "--- " + i18n.T["OPT_DELETE_PROJECT"] + " ---" + colorReset)
		fmt.Println(colorRed + i18n.T["MSG_DELETE_WARNING"] + colorReset)
		fmt.Println(colorYellow + i18n.T["MSG_DELETE_CONFIRM"] + colorReset)
		fmt.Println("1. " + i18n.T["OPT_BACK"])
		fmt.Println("2. " + i18n.T["OPT_EXIT"])
		fmt.Printf("\n%s%s: %s", colorGreen, i18n.T["LBL_CHOICE_PROMPT"], colorReset)

		choice := readUserInput()
		fmt.Println("--------------------------------------------------")

		switch choice {
		case "delete":
			if err := controller.DeleteProject(ctx, projectID); err != nil {
				fmt.Printf("%s%s: %v%s\n", colorRed, i18n.T["LBL_ERROR"], err, colorReset)
				return false, false
			}
			fmt.Println(colorGreen + i18n.T["MSG_PROJECT_DELETED"] + colorReset)
			return true, false
		case "1":
			return false, false
		case "2":
			return false, true
		default:
			fmt.Println(colorRed + i18n.T["ERR_INVALID_CHOICE"] + colorReset)
		}
	}
}

func formatBytes(bytes int64) string {
	const (
		kb = 1024
		mb = kb * 1024
		gb = mb * 1024
	)
	switch {
	case bytes >= gb:
		return fmt.Sprintf("%.2f GB", float64(bytes)/float64(gb))
	case bytes >= mb:
		return fmt.Sprintf("%.2f MB", float64(bytes)/float64(mb))
	case bytes >= kb:
		return fmt.Sprintf("%.2f KB", float64(bytes)/float64(kb))
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}

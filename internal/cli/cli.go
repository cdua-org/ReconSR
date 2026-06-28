package cli

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

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
			graph, err := controller.GetActiveGraph(ctx, false)
			if err != nil {
				fmt.Printf("%s: %v\n", i18n.T["LBL_ERROR"], err)
				continue
			}
			filename, err := report.GenerateTreeHTML(graph)
			if err != nil {
				fmt.Printf("%s: %v\n", i18n.T["LBL_ERROR"], err)
			} else {
				fmt.Printf("\n%s: %s\n", i18n.T["MSG_REPORT_SAVED"], filename)
			}
		case "3":
			fmt.Println("\n" + i18n.T["MSG_GENERATING_GRAPH"])
			graph, err := controller.GetActiveGraph(ctx, true)
			if err != nil {
				fmt.Printf("%s: %v\n", i18n.T["LBL_ERROR"], err)
				continue
			}
			if len(graph.Nodes) >= 5000 {
				fmt.Println(colorYellow + i18n.T["MSG_LARGE_GRAPH_WARNING"] + colorReset)
			}
			filename, err := report.GenerateHTML(ctx, graph)
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
	logo := `
  ░█▀█░█▀▀░█▀▀░█▀█░█▄░█░█▀▀░█▀█
  ░█▀▄░█▀▀░█░░░█░█░█░▀█░▀▀█░█▀▄
  ░▀░▀░▀▀▀░▀▀▀░▀▀▀░▀░░▀░▀▀▀░▀░▀`

	fmt.Println(colorMagenta + colorBold + logo + colorReset)
	fmt.Println()
	fmt.Printf(colorCyan+"  :: %s %s ::"+colorReset+"\n", AppName, AppVersion)
	fmt.Printf(colorCyan+"  :: %s ::"+colorReset+"\n", AppDesc)
	fmt.Printf(colorCyan+"  :: %s ::"+colorReset+"\n", AppStage)
	fmt.Println()

	fmt.Println(colorCyan + colorBold + "[ " + i18n.T["LBL_SYS_INFO"] + " ]" + colorReset)

	fmt.Printf("  + %-20s %s\n", i18n.T["MSG_INIT_CORE"]+":", colorGreen+i18n.T["MSG_STATUS_READY"]+colorReset)

	totalMods, _, totalFuncs, _, _ := controller.GetSystemStatus(ctx)
	modInfo := fmt.Sprintf("%d | %d", totalMods, totalFuncs)
	fmt.Printf("  + %-20s %s\n", i18n.T["LBL_MODS"]+" | "+i18n.T["LBL_FUNCS"]+":", modInfo)

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

			var catKeys []string
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

				var keys []string
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

// GetRawTarget extracts the target from args.
func GetRawTarget(args []string) string {
	if len(args) < 2 {
		fmt.Printf("\n%s%s %s", colorGreen, i18n.T["LBL_INPUT_TARGET_PROMPT"]+":", colorReset)
		target := readUserInput()
		if target == "" {
			fmt.Println(i18n.T["LBL_USAGE"] + ": " + args[0] + " <" + i18n.T["LBL_TARGET_HINT"] + ">")
			os.Exit(1)
		}
		return target
	}
	return args[1]
}

// HandleUserInput manages the UI loop for projects and actions.
func HandleUserInput(ctx context.Context, rawInput string) bool {
	targetType, targetValue, err := controller.ValidateTarget("auto", rawInput)
	if err != nil {
		switch err {
		case controller.ErrOutOfScope:
			fmt.Println(colorRed + i18n.T["ERR_OUT_OF_SCOPE"] + colorReset)
		case controller.ErrUnsupportedType:
			fmt.Println(colorRed + i18n.T["ERR_UNSUPPORTED_TYPE"] + colorReset)
		default:
			fmt.Println(colorRed + i18n.T["ERR_INVALID_FORMAT"] + colorReset)
		}
		os.Exit(1)
	}

	for {
		if projectID := controller.GetActiveProjectID(); projectID != "" {
			if run := handleProjectActions(ctx, projectID, targetType, targetValue); run != nil {
				if *run {
					printReconStatus(false)
				}
				return *run
			}
			controller.ClearActiveProject()
			continue
		}

		fmt.Printf("\n%s%s: %s%s%s%s (%s)\n", colorCyan, i18n.T["LBL_TARGET"], colorReset, colorBold, targetValue, colorReset, targetType)

		tM, aM, tF, aF, _ := controller.GetSystemStatus(ctx)
		fmt.Printf("%s%s:%s %d/%d %s, %d/%d %s\n", colorCyan, i18n.T["MSG_ACTIVE_TOOLS"], colorReset, aM, tM, i18n.T["LBL_MODS"], aF, tF, i18n.T["LBL_FUNCS"])
		projects, hasModules, hasActiveFuncs, err := controller.GetProjects(ctx, targetType, targetValue)
		if err != nil {
			fmt.Printf("%s%s: %v%s\n", colorRed, i18n.T["LBL_ERROR"], err, colorReset)
			os.Exit(1)
		}

		if !hasModules {
			fmt.Println(colorRed + i18n.T["ERR_NO_MODULES"] + ": '" + targetType + "'" + colorReset)
			os.Exit(0)
		}

		if !hasActiveFuncs && len(projects) == 0 {
			fmt.Println(colorRed + i18n.T["ERR_NO_ACTIVE_FUNCS"] + colorReset)
			fmt.Println("\n" + colorYellow + "[!] " + i18n.T["MSG_CONFIG_INFO"] + colorReset)

			fmt.Printf("\n1. %s\n", i18n.T["OPT_EXIT"])
			fmt.Printf("\n%s%s: %s", colorGreen, i18n.T["LBL_CHOICE_PROMPT"], colorReset)

			choice := readUserInput()
			fmt.Println("--------------------------------------------------")

			if choice == "0" {
				handleModuleConfiguration(ctx)
				continue
			}

			var idx int
			if _, err := fmt.Sscanf(choice, "%d", &idx); err != nil {
				fmt.Println(colorRed + i18n.T["ERR_INVALID_CHOICE"] + colorReset)
				continue
			}

			if idx == 1 {
				return false
			}
			fmt.Println(colorRed + i18n.T["ERR_INVALID_CHOICE"] + colorReset)
			continue
		}

		fmt.Println("\n" + colorYellow + "[!] " + i18n.T["MSG_CONFIG_INFO"] + colorReset)

		fmt.Println("\n" + colorCyan + colorBold + "--- " + i18n.T["MSG_PROJECTS_EXIST_2"] + " ---" + colorReset)
		if !hasActiveFuncs {
			fmt.Printf("1. %s %s(%s)%s\n", i18n.T["OPT_NEW_PROJECT"], colorRed, i18n.T["ERR_NO_ACTIVE_FUNCS"], colorReset)
		} else {
			fmt.Printf("1. %s\n", i18n.T["OPT_NEW_PROJECT"])
		}

		for i, p := range projects {
			fmt.Printf("%d. %s %s (%s: %s)\n", i+2, i18n.T["OPT_CONTINUE_PROJECT"], p.Name, i18n.T["LBL_CREATED"], p.CreatedAt.Format("2006-01-02 15:04:05"))
		}

		exitIdx := len(projects) + 2
		fmt.Printf("%d. %s\n", exitIdx, i18n.T["OPT_EXIT"])
		fmt.Printf("\n%s%s: %s", colorGreen, i18n.T["LBL_CHOICE_PROMPT"], colorReset)

		choice := readUserInput()
		fmt.Println("--------------------------------------------------")

		var idx int
		// Special handling for '0' (configuration)
		if choice == "0" {
			handleModuleConfiguration(ctx)
			continue
		}

		if _, err := fmt.Sscanf(choice, "%d", &idx); err != nil {
			fmt.Println(colorRed + i18n.T["ERR_INVALID_CHOICE"] + colorReset)
			continue
		}

		if idx == exitIdx {
			return false
		} else if idx == 1 {
			if !hasActiveFuncs {
				fmt.Println(colorRed + i18n.T["ERR_INVALID_CHOICE"] + colorReset)
				continue
			}
			newID, err := controller.CreateNewProject(ctx, targetType, targetValue)
			if err != nil {
				fmt.Printf("%s: %v\n", i18n.T["LBL_ERROR"], err)
				continue
			}
			controller.SetActiveProject(newID)
			printReconStatus(false)
			return true
		} else if idx >= 2 && idx <= len(projects)+1 {
			controller.SetActiveProject(projects[idx-2].DBIdentifier)
		} else {
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

		var idx int
		if _, err := fmt.Sscanf(choice, "%d", &idx); err != nil {
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

func handleProjectActions(ctx context.Context, projectID, targetType, targetValue string) *bool {
	for {
		pending, errs, err := controller.GetProjectStatus(ctx, projectID)
		if err != nil {
			fmt.Printf("%s%s: %v%s\n", colorRed, i18n.T["LBL_ERROR"], err, colorReset)
			return nil
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

		fmt.Println("\n" + colorCyan + colorBold + "--- " + i18n.T["MSG_PROJ_ACTION"] + " ---" + colorReset)
		fmt.Printf("1. %s\n", i18n.T["OPT_FULL_RESCAN"])
		optIdx := 2
		var contOpt, retryOpt, resOpt, backOpt, exitOpt int

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

		backOpt = optIdx
		fmt.Printf("%d. %s\n", optIdx, i18n.T["OPT_BACK"])
		optIdx++

		exitOpt = optIdx
		fmt.Printf("%d. %s\n", optIdx, i18n.T["OPT_EXIT"])

		fmt.Printf("\n%s%s: %s", colorGreen, i18n.T["LBL_CHOICE_PROMPT"], colorReset)
		choice := readUserInput()
		fmt.Println("--------------------------------------------------")
		var idx int
		if _, err := fmt.Sscanf(choice, "%d", &idx); err != nil {
			fmt.Println(colorRed + i18n.T["ERR_INVALID_CHOICE"] + colorReset)
			continue
		}

		run := true
		stop := false

		if idx == 1 {
			if err := controller.ResetProjectLog(ctx, projectID, true, false); err != nil {
				fmt.Printf("%s%s: %v%s\n", colorRed, i18n.T["LBL_ERROR"], err, colorReset)
				continue
			}
			if err := controller.SetResumeSession(ctx, projectID, true, false); err != nil {
				fmt.Printf("%s%s: %v%s\n", colorRed, i18n.T["LBL_ERROR"], err, colorReset)
				continue
			}
			return &run
		} else if contOpt > 0 && idx == contOpt {
			if err := controller.SetResumeSession(ctx, projectID, true, false); err != nil {
				fmt.Printf("%s%s: %v%s\n", colorRed, i18n.T["LBL_ERROR"], err, colorReset)
				continue
			}
			return &run
		} else if retryOpt > 0 && idx == retryOpt {
			if err := controller.SetResumeSession(ctx, projectID, false, true); err != nil {
				fmt.Printf("%s%s: %v%s\n", colorRed, i18n.T["LBL_ERROR"], err, colorReset)
				continue
			}
			return &run
		} else if idx == resOpt {
			ShowResultsMenu(ctx)
			continue
		} else if idx == backOpt {
			return nil
		} else if idx == exitOpt {
			return &stop
		}
		fmt.Println(colorRed + i18n.T["ERR_INVALID_CHOICE"] + colorReset)
	}
}

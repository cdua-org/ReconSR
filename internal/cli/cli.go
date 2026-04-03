package cli

import (
	"context"
	"fmt"
	"os"
	"sort"

	"cdua-org/ReconSR/internal/controller"
	"cdua-org/ReconSR/internal/i18n"
	"cdua-org/ReconSR/internal/report"
)

// ShowResultsMenu presents visualization options.
func ShowResultsMenu(ctx context.Context) {
	graph, err := controller.GetActiveGraph(ctx)
	if err != nil {
		fmt.Printf("%s: %v\n", i18n.T["LBL_ERROR"], err)
		return
	}

	for {
		fmt.Println("\n" + colorCyan + colorBold + "--- " + i18n.T["OPT_SHOW_RESULTS"] + " ---" + colorReset)
		fmt.Println("1. " + i18n.T["OPT_TREE_CONSOLE"])
		fmt.Println("2. " + i18n.T["OPT_GRAPH_HTML"])
		fmt.Println("3. " + i18n.T["OPT_BACK"])
		fmt.Println("4. " + i18n.T["OPT_EXIT"])
		fmt.Print("\n" + colorGreen + i18n.T["LBL_CHOICE_PROMPT"] + ": " + colorReset)

		var choice string
		if _, err := fmt.Scanln(&choice); err != nil {
			return
		}
		fmt.Println("--------------------------------------------------")

		switch choice {
		case "1":
			report.RenderResultsTree(graph)
		case "2":
			filename, err := report.GenerateHTML(graph)
			if err != nil {
				fmt.Printf("%s: %v\n", i18n.T["LBL_ERROR"], err)
			} else {
				fmt.Printf("\n%s: %s\n", i18n.T["MSG_REPORT_SAVED"], filename)
			}
		case "3":
			return
		case "4":
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
	fmt.Printf(colorCyan+"  :: %s %s ::"+colorReset+"\n", i18n.T["BANNER_NAME"], i18n.T["BANNER_VERSION"])
	fmt.Printf(colorCyan+"  :: %s ::"+colorReset+"\n", i18n.T["BANNER_DESC"])
	fmt.Printf(colorCyan+"  :: %s ::"+colorReset+"\n", i18n.T["BANNER_STAGE"])
	fmt.Println()

	fmt.Println(colorCyan + colorBold + "[ " + i18n.T["LBL_SYS_INFO"] + " ]" + colorReset)

	fmt.Printf("  + %-18s %s\n", i18n.T["MSG_INIT_CORE"]+":", colorGreen+i18n.T["MSG_STATUS_READY"]+colorReset)

	totalMods, _, totalFuncs, _, _ := controller.GetSystemStatus(ctx)
	modInfo := fmt.Sprintf("%d/%d", totalMods, totalFuncs)
	fmt.Printf("  + %-18s %s\n", i18n.T["LBL_MODS"]+"/"+i18n.T["LBL_FUNCS"]+":", modInfo)

	fmt.Printf("  + %-18s %s\n", i18n.T["MSG_CONN_DB"]+":", colorGreen+i18n.T["MSG_STATUS_CONN"]+colorReset)
	fmt.Println(colorCyan + "--------------------------------------------------" + colorReset)
}

// ShowScanCompleteBanner prints the post-scan status message and entity statistics.
func ShowScanCompleteBanner(ctx context.Context) {
	fmt.Println("\n" + colorGreen + colorBold + "--------------------------------------------------" + colorReset)
	fmt.Println(colorGreen + colorBold + "[*] " + i18n.T["MSG_SCAN_COMPLETE"] + colorReset)

	if projectID := controller.GetActiveProjectID(); projectID != "" {
		graph, err := controller.GetProjectGraph(ctx, projectID)
		if err == nil {
			nodes := make(map[string]bool)
			stats := make(map[string]int)
			for _, edge := range graph.Edges {
				src := edge.Source.Type + ":" + edge.Source.Value
				dst := edge.Target.Type + ":" + edge.Target.Value
				if !nodes[src] {
					nodes[src] = true
					stats[edge.Source.Type]++
				}
				if !nodes[dst] {
					nodes[dst] = true
					stats[edge.Target.Type]++
				}
			}
			if len(nodes) > 0 {
				fmt.Printf(colorCyan+"Total entities: %d"+colorReset+"\n", len(nodes))
				for t, count := range stats {
					fmt.Printf("  - %s: %d\n", t, count)
				}
			}
		}
	}
	fmt.Println(colorGreen + colorBold + "--------------------------------------------------" + colorReset)
}

// GetRawTarget extracts the target from args.
func GetRawTarget(args []string) string {
	if len(args) < 2 {
		fmt.Println(i18n.T["LBL_USAGE"] + ": " + args[0] + " <" + i18n.T["LBL_DOMAIN"] + ">")
		os.Exit(1)
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
				return *run
			}
			controller.ClearActiveProject()
			continue
		}

		fmt.Printf("\n%s%s:%s %s%s%s (%s)\n", colorCyan, i18n.T["LBL_TARGET"], colorReset, colorBold, targetValue, colorReset, targetType)

		tM, aM, tF, aF, _ := controller.GetSystemStatus(ctx)
		fmt.Printf("%s%s:%s  %d/%d %s, %d/%d %s\n", colorCyan, i18n.T["LBL_ACTIVE_TOOLS"], colorReset, aM, tM, i18n.T["LBL_MODS"], aF, tF, i18n.T["LBL_FUNCS"])
		fmt.Println("\n" + colorYellow + "[!] " + i18n.T["MSG_CONFIG_INFO"] + colorReset)

		projects, hasModules, err := controller.GetProjects(ctx, targetType, targetValue)
		if err != nil {
			fmt.Printf("%s%s: %v%s\n", colorRed, i18n.T["LBL_ERROR"], err, colorReset)
			os.Exit(1)
		}

		if !hasModules {
			fmt.Println(colorRed + i18n.T["ERR_NO_MODULES"] + colorReset)
			if len(projects) == 0 {
				os.Exit(0)
			}
		}

		fmt.Println("\n" + colorCyan + colorBold + "--- " + i18n.T["MSG_PROJECTS_EXIST_2"] + " ---" + colorReset)
		fmt.Printf("1. %s\n", i18n.T["OPT_NEW_PROJECT"])

		for i, p := range projects {
			fmt.Printf("%d. %s %s (%s: %s)\n", i+2, i18n.T["OPT_CONTINUE_PROJECT"], p.Name, i18n.T["LBL_CREATED"], p.CreatedAt.Format("2006-01-02 15:04:05"))
		}

		exitIdx := len(projects) + 2
		fmt.Printf("%d. %s\n", exitIdx, i18n.T["OPT_EXIT"])
		fmt.Printf("\n%s%s: %s", colorGreen, i18n.T["LBL_CHOICE_PROMPT"], colorReset)

		var choice string
		if _, err := fmt.Scanln(&choice); err != nil {
			os.Exit(0)
		}
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
			newID, err := controller.CreateNewProject(ctx, targetType, targetValue)
			if err != nil {
				fmt.Printf("%s: %v\n", i18n.T["LBL_ERROR"], err)
				continue
			}
			controller.SetActiveProject(newID)
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

	type flatFunc struct {
		modName string
		fnName  string
	}

	for {
		var flatList []flatFunc
		mods := make([]string, 0, len(settings))
		for m := range settings {
			mods = append(mods, m)
		}
		sort.Strings(mods)

		for _, m := range mods {
			fns := settings[m]
			fnNames := make([]string, 0, len(fns))
			for f := range fns {
				fnNames = append(fnNames, f)
			}
			sort.Strings(fnNames)
			for _, f := range fnNames {
				flatList = append(flatList, flatFunc{m, f})
			}
		}

		fmt.Println("\n" + colorCyan + colorBold + "--- " + i18n.T["LBL_CONFIG_TITLE"] + " ---" + colorReset)

		lastMod := ""
		for i, item := range flatList {
			if item.modName != lastMod {
				fmt.Printf("\n%s[ %s ]%s\n", colorCyan, item.modName, colorReset)
				lastMod = item.modName
			}

			status := i18n.T["LBL_DISABLED"]
			color := colorRed
			if settings[item.modName][item.fnName] {
				status = i18n.T["LBL_ENABLED"]
				color = colorGreen
			}
			fmt.Printf("%d. %s%s%s %s\n", i+1, color, status, colorReset, item.fnName)
		}

		saveIdx := len(flatList) + 1
		fmt.Printf("\n%d. %s\n", saveIdx, i18n.T["OPT_SAVE_EXIT"])

		fmt.Printf("\n%s%s: %s", colorGreen, i18n.T["LBL_CHOICE_PROMPT"], colorReset)
		var choice string
		if _, err := fmt.Scanln(&choice); err != nil {
			return
		}

		var idx int
		if _, err := fmt.Sscanf(choice, "%d", &idx); err != nil {
			continue
		}

		if idx == saveIdx {
			if err := controller.UpdateModuleSettings(ctx, settings); err != nil {
				fmt.Printf("%s%s: %v%s\n", colorRed, i18n.T["LBL_ERROR"], err, colorReset)
			} else {
				fmt.Println(colorGreen + i18n.T["MSG_CONFIG_SAVED"] + colorReset)
			}
			return
		}

		if idx > 0 && idx <= len(flatList) {
			target := flatList[idx-1]
			settings[target.modName][target.fnName] = !settings[target.modName][target.fnName]
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
				fmt.Printf("%s[%s]:%s\n", colorYellow, i18n.T["MSG_PENDING_FOUND"], colorReset)
				for _, p := range pending {
					fmt.Println(colorYellow + "  - " + p + colorReset)
				}
			}
			if len(errs) > 0 {
				fmt.Printf("%s[%s]:%s\n", colorRed, i18n.T["MSG_ERRORS_FOUND"], colorReset)
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
		var choice string
		if _, err := fmt.Scanln(&choice); err != nil {
			return nil
		}
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

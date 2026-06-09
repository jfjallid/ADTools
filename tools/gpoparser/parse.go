package main

// parseAllGPOs reads and parses every known SYSVOL file for each GPO from src,
// filling in the GPO's Computer / User configuration settings.
func parseAllGPOs(src fileSource, gpos []*GPO) {
	for _, g := range gpos {
		for _, f := range gpoFiles {
			data, ok, err := src.read(g, f.scope, f.rel)
			if err != nil {
				logger.Debugf("read %s\\%s for %s: %v\n", f.scope, f.rel, g.GUID, err)
				continue
			}
			if !ok || len(data) == 0 {
				continue
			}
			cs := &g.Computer
			if f.scope == "User" {
				cs = &g.User
			}
			dispatchParser(f.kind, f.scope, data, cs)
		}
	}
}

// dispatchParser routes raw file bytes to the parser for its kind.
func dispatchParser(kind, scope string, data []byte, cs *ConfigSettings) {
	switch kind {
	case "gpttmpl":
		parseGptTmpl(data, cs)
	case "registrypol":
		hive := "HKLM"
		if scope == "User" {
			hive = "HKCU"
		}
		parseRegistryPol(data, hive, cs)
	case "groups":
		parseGPPGroups(data, cs)
		parseGPPLocalUsers(data, cs)
	case "registryxml":
		parseGPPRegistry(data, cs)
	case "tasks":
		parseGPPTasks(data, cs)
	case "services":
		parseGPPServices(data, cs)
	case "datasources":
		parseGPPDataSources(data, cs)
	case "drives":
		parseGPPDrives(data, cs)
	case "files":
		parseGPPFiles(data, cs)
	case "shortcuts":
		parseGPPShortcuts(data, cs)
	case "printers":
		parseGPPPrinters(data, cs)
	case "envvars":
		parseGPPEnvVars(data, cs)
	case "scripts":
		parseScripts(data, false, cs)
	case "psscripts":
		parseScripts(data, true, cs)
	}
}

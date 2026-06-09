package main

import (
	"sort"
	"strconv"
	"strings"
)

// parseScripts parses a scripts.ini / psscripts.ini (UTF-16LE INI) into script
// entries. Sections are Logon/Logoff/Startup/Shutdown; within each, scripts are
// numbered: "<N>CmdLine" and "<N>Parameters".
func parseScripts(data []byte, powershell bool, cs *ConfigSettings) {
	text := decodeUTF16(data)
	for _, sec := range parseINI(text) {
		stype := canonicalScriptType(sec.name)
		if stype == "" {
			continue
		}
		type entry struct{ cmd, params string }
		byIdx := map[int]*entry{}
		var order []int
		for _, e := range sec.entries {
			idx, field, ok := splitScriptKey(e.key)
			if !ok {
				continue
			}
			t := byIdx[idx]
			if t == nil {
				t = &entry{}
				byIdx[idx] = t
				order = append(order, idx)
			}
			switch field {
			case "cmdline":
				t.cmd = e.value
			case "parameters":
				t.params = e.value
			}
		}
		sort.Ints(order)
		for _, idx := range order {
			t := byIdx[idx]
			if strings.TrimSpace(t.cmd) == "" {
				continue
			}
			cs.Scripts = append(cs.Scripts, ScriptEntry{
				Type:       stype,
				Order:      idx,
				CmdLine:    t.cmd,
				Parameters: t.params,
				PowerShell: powershell,
			})
		}
	}
}

func canonicalScriptType(name string) string {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "logon":
		return "Logon"
	case "logoff":
		return "Logoff"
	case "startup":
		return "Startup"
	case "shutdown":
		return "Shutdown"
	default:
		return ""
	}
}

// splitScriptKey parses "<N>CmdLine"/"<N>Parameters" into the index and the
// lower-cased field name.
func splitScriptKey(key string) (idx int, field string, ok bool) {
	key = strings.TrimSpace(key)
	i := 0
	for i < len(key) && key[i] >= '0' && key[i] <= '9' {
		i++
	}
	if i == 0 {
		return 0, "", false
	}
	n, err := strconv.Atoi(key[:i])
	if err != nil {
		return 0, "", false
	}
	switch strings.ToLower(key[i:]) {
	case "cmdline":
		return n, "cmdline", true
	case "parameters":
		return n, "parameters", true
	default:
		return 0, "", false
	}
}

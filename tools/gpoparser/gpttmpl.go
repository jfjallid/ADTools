package main

import "strings"

// parseGptTmpl parses a SECEDIT security template (GptTmpl.inf, UTF-16LE) into
// the Computer scope of a ConfigSettings: privilege rights, restricted-group
// membership, registry values, system access (password/lockout policy) and
// service startup settings.
func parseGptTmpl(data []byte, cs *ConfigSettings) {
	text := decodeUTF16(data)
	sections := parseINI(text)

	if s := section(sections, "Privilege Rights"); s != nil {
		for _, e := range s.entries {
			members := parsePrincipalList(e.value)
			if len(members) == 0 {
				continue
			}
			cs.Privileges = append(cs.Privileges, PrivilegeRight{
				Privilege:   e.key,
				Description: privilegeDescription(e.key),
				Members:     members,
				Dangerous:   isDangerousPrivilege(e.key),
			})
		}
	}

	if s := section(sections, "Group Membership"); s != nil {
		// Keys look like "<group>__Members" or "<group>__Memberof"; <group> is a
		// *SID or an account name. Coalesce both halves per group.
		byGroup := map[string]*GroupMembership{}
		var order []string
		groupOf := func(raw string) (Principal, string) {
			if strings.HasPrefix(raw, "*") {
				p := principalFromSID(strings.TrimPrefix(raw, "*"))
				return p, p.SID
			}
			return Principal{Name: raw}, strings.ToLower(raw)
		}
		for _, e := range s.entries {
			var suffix string
			var base string
			switch {
			case strings.HasSuffix(e.key, "__Members"):
				suffix = "members"
				base = strings.TrimSuffix(e.key, "__Members")
			case strings.HasSuffix(e.key, "__Memberof"):
				suffix = "memberof"
				base = strings.TrimSuffix(e.key, "__Memberof")
			default:
				continue
			}
			groupPrincipal, gkey := groupOf(base)
			gm := byGroup[gkey]
			if gm == nil {
				gm = &GroupMembership{Source: "gpttmpl", Action: "SET", Group: groupPrincipal}
				byGroup[gkey] = gm
				order = append(order, gkey)
			}
			list := parsePrincipalList(e.value)
			if suffix == "members" {
				gm.Members = append(gm.Members, list...)
			} else {
				gm.MemberOf = append(gm.MemberOf, list...)
			}
		}
		for _, k := range order {
			cs.GroupMemberships = append(cs.GroupMemberships, *byGroup[k])
		}
	}

	if s := section(sections, "Registry Values"); s != nil {
		for _, e := range s.entries {
			rtype, val := splitRegistryValue(e.value)
			cs.RegistryValues = append(cs.RegistryValues, RegistrySetting{
				Source: "gpttmpl",
				Key:    e.key,
				Type:   rtype,
				Value:  val,
			})
		}
	}

	if s := section(sections, "System Access"); s != nil {
		for _, e := range s.entries {
			cs.SystemAccess = append(cs.SystemAccess, KeyValue{Key: e.key, Value: e.value})
		}
	}

	if s := section(sections, "Service General Setting"); s != nil {
		for _, e := range s.entries {
			// value: <startupType>,"<SDDL>"
			startType, sddl := splitServiceSetting(e.value)
			cs.Services = append(cs.Services, ServiceSetting{
				Source:    "gpttmpl",
				Name:      strings.Trim(e.key, `"`),
				StartType: serviceStartName(startType),
				SDDL:      sddl,
			})
		}
	}
}

// splitRegistryValue splits a SECEDIT [Registry Values] value of the form
// "<typeNum>,<data>" into a friendly type name and the data.
func splitRegistryValue(v string) (typeName, data string) {
	parts := strings.SplitN(v, ",", 2)
	if len(parts) == 2 {
		return regTypeName(strings.TrimSpace(parts[0])), strings.TrimSpace(parts[1])
	}
	return "", strings.TrimSpace(v)
}

func splitServiceSetting(v string) (startType, sddl string) {
	parts := strings.SplitN(v, ",", 2)
	if len(parts) == 0 {
		return "", ""
	}
	startType = strings.TrimSpace(parts[0])
	if len(parts) == 2 {
		sddl = strings.Trim(strings.TrimSpace(parts[1]), `"`)
	}
	return
}

// regTypeName maps a SECEDIT/registry REG_* type number to a friendly name.
func regTypeName(n string) string {
	switch strings.TrimSpace(n) {
	case "1":
		return "REG_SZ"
	case "2":
		return "REG_EXPAND_SZ"
	case "3":
		return "REG_BINARY"
	case "4":
		return "REG_DWORD"
	case "5":
		return "REG_DWORD_BIG_ENDIAN"
	case "7":
		return "REG_MULTI_SZ"
	case "11":
		return "REG_QWORD"
	default:
		if n == "" {
			return ""
		}
		return "REG_TYPE_" + n
	}
}

// serviceStartName maps a service startup-type number to a friendly name.
func serviceStartName(n string) string {
	switch strings.TrimSpace(n) {
	case "2":
		return "Automatic"
	case "3":
		return "Manual"
	case "4":
		return "Disabled"
	default:
		return n
	}
}

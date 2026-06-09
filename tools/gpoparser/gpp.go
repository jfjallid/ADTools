package main

import (
	"encoding/xml"
	"io"
	"strings"
)

// newXMLDecoder returns an xml.Decoder over data, transparently handling a
// UTF-16/UTF-8 BOM and tolerating any declared charset (GPP files are UTF-8 but
// we don't want an encoding mismatch to abort parsing).
func newXMLDecoder(data []byte) *xml.Decoder {
	dec := xml.NewDecoder(strings.NewReader(decodeUTF16(data)))
	dec.CharsetReader = func(_ string, input io.Reader) (io.Reader, error) { return input, nil }
	return dec
}

// forEachElement invokes fn for every start element whose local name matches
// local, at any nesting depth. DecodeElement consumes the matched subtree, so
// GPP <Collection> wrappers (used for item-level targeting) are handled without
// special-casing.
func forEachElement(data []byte, local string, fn func(d *xml.Decoder, start xml.StartElement)) {
	dec := newXMLDecoder(data)
	for {
		tok, err := dec.Token()
		if err != nil {
			return // includes io.EOF and malformed tails
		}
		if se, ok := tok.(xml.StartElement); ok && se.Name.Local == local {
			fn(dec, se)
		}
	}
}

// gppAction expands a GPP single-letter action code.
func gppAction(code string) string {
	switch strings.ToUpper(strings.TrimSpace(code)) {
	case "C":
		return "Create"
	case "R":
		return "Replace"
	case "U":
		return "Update"
	case "D":
		return "Delete"
	default:
		return strings.TrimSpace(code)
	}
}

// ---- Groups.xml ----------------------------------------------------------

type gppGroup struct {
	Name       string `xml:"name,attr"`
	Properties struct {
		Action    string `xml:"action,attr"`
		GroupSid  string `xml:"groupSid,attr"`
		GroupName string `xml:"groupName,attr"`
		Members   struct {
			Member []struct {
				Name   string `xml:"name,attr"`
				Action string `xml:"action,attr"`
				SID    string `xml:"sid,attr"`
			} `xml:"Member"`
		} `xml:"Members"`
	} `xml:"Properties"`
}

func parseGPPGroups(data []byte, cs *ConfigSettings) {
	forEachElement(data, "Group", func(d *xml.Decoder, start xml.StartElement) {
		var g gppGroup
		if err := d.DecodeElement(&g, &start); err != nil {
			return
		}
		groupName := g.Properties.GroupName
		if groupName == "" {
			groupName = g.Name
		}
		gm := GroupMembership{
			Source: "gpp",
			Action: gppAction(g.Properties.Action),
			Group:  Principal{SID: g.Properties.GroupSid, Name: stripBuiltinSuffix(groupName)},
		}
		for _, m := range g.Properties.Members.Member {
			// Only additions express "principal X gains rights on the group".
			if !strings.EqualFold(strings.TrimSpace(m.Action), "ADD") {
				continue
			}
			gm.Members = append(gm.Members, Principal{SID: m.SID, Name: m.Name})
		}
		if len(gm.Members) > 0 || gm.Action == "Delete" {
			cs.GroupMemberships = append(cs.GroupMemberships, gm)
		}
	})
}

// stripBuiltinSuffix turns "Administrators (built-in)" into "Administrators".
func stripBuiltinSuffix(name string) string {
	if i := strings.Index(name, " (built-in)"); i >= 0 {
		return strings.TrimSpace(name[:i])
	}
	return name
}

// gppLocalUser covers the <User> elements of Groups.xml (local account
// management), which can carry an MS14-025 cpassword.
type gppLocalUser struct {
	Name       string `xml:"name,attr"`
	Properties struct {
		Action    string `xml:"action,attr"`
		UserName  string `xml:"userName,attr"`
		NewName   string `xml:"newName,attr"`
		CPassword string `xml:"cpassword,attr"`
	} `xml:"Properties"`
}

// parseGPPLocalUsers extracts the <User> entries of Groups.xml. It shares the
// file with parseGPPGroups (both are dispatched for the "groups" kind).
func parseGPPLocalUsers(data []byte, cs *ConfigSettings) {
	forEachElement(data, "User", func(d *xml.Decoder, start xml.StartElement) {
		var u gppLocalUser
		if err := d.DecodeElement(&u, &start); err != nil {
			return
		}
		name := firstNonEmpty(u.Properties.UserName, u.Name)
		if name == "" && u.Properties.CPassword == "" {
			return
		}
		cs.LocalUsers = append(cs.LocalUsers, LocalUser{
			Name:      name,
			UserName:  u.Properties.UserName,
			Action:    gppAction(u.Properties.Action),
			CPassword: u.Properties.CPassword,
		})
	})
}

// ---- Registry.xml --------------------------------------------------------

type gppRegistry struct {
	Properties struct {
		Action string `xml:"action,attr"`
		Hive   string `xml:"hive,attr"`
		Key    string `xml:"key,attr"`
		Name   string `xml:"name,attr"`
		Type   string `xml:"type,attr"`
		Value  string `xml:"value,attr"`
	} `xml:"Properties"`
}

func parseGPPRegistry(data []byte, cs *ConfigSettings) {
	forEachElement(data, "Registry", func(d *xml.Decoder, start xml.StartElement) {
		var r gppRegistry
		if err := d.DecodeElement(&r, &start); err != nil {
			return
		}
		p := r.Properties
		if p.Key == "" && p.Name == "" {
			return
		}
		cs.RegistryValues = append(cs.RegistryValues, RegistrySetting{
			Source: "gpp",
			Action: gppAction(p.Action),
			Hive:   p.Hive,
			Key:    p.Key,
			Name:   p.Name,
			Type:   p.Type,
			Value:  p.Value,
		})
	})
}

// ---- ScheduledTasks.xml --------------------------------------------------

// gppTaskV1 covers <Task> and <ImmediateTask> (Windows XP/2003 style).
type gppTaskV1 struct {
	Name       string `xml:"name,attr"`
	Properties struct {
		Action    string `xml:"action,attr"`
		Name      string `xml:"name,attr"`
		AppName   string `xml:"appName,attr"`
		Args      string `xml:"args,attr"`
		RunAs     string `xml:"runAs,attr"`
		CPassword string `xml:"cpassword,attr"`
	} `xml:"Properties"`
}

// gppTaskV2 covers <TaskV2> and <ImmediateTaskV2> (Vista+).
type gppTaskV2 struct {
	Name       string `xml:"name,attr"`
	Properties struct {
		Action    string `xml:"action,attr"`
		Name      string `xml:"name,attr"`
		RunAs     string `xml:"runAs,attr"`
		CPassword string `xml:"cpassword,attr"`
		Task      struct {
			Principals struct {
				Principal []struct {
					UserId string `xml:"UserId"`
				} `xml:"Principal"`
			} `xml:"Principals"`
			Actions struct {
				Exec []struct {
					Command   string `xml:"Command"`
					Arguments string `xml:"Arguments"`
				} `xml:"Exec"`
			} `xml:"Actions"`
		} `xml:"Task"`
	} `xml:"Properties"`
}

func parseGPPTasks(data []byte, cs *ConfigSettings) {
	for _, elem := range []string{"Task", "ImmediateTask"} {
		forEachElement(data, elem, func(d *xml.Decoder, start xml.StartElement) {
			var t gppTaskV1
			if err := d.DecodeElement(&t, &start); err != nil {
				return
			}
			name := firstNonEmpty(t.Properties.Name, t.Name)
			// A <Task>/<ImmediateTask> element always carries a <Properties>
			// child; the V2 inner <Task> (nested in Properties) does not, and
			// would decode to an empty record. Skip those so the V1 walk does
			// not double-count V2 tasks.
			if name == "" && t.Properties.AppName == "" && t.Properties.Args == "" {
				return
			}
			cs.ScheduledTasks = append(cs.ScheduledTasks, ScheduledTask{
				Name:      name,
				Type:      elem,
				Action:    gppAction(t.Properties.Action),
				Command:   t.Properties.AppName,
				Arguments: t.Properties.Args,
				RunAs:     t.Properties.RunAs,
				CPassword: t.Properties.CPassword,
			})
		})
	}
	for _, elem := range []string{"TaskV2", "ImmediateTaskV2"} {
		forEachElement(data, elem, func(d *xml.Decoder, start xml.StartElement) {
			var t gppTaskV2
			if err := d.DecodeElement(&t, &start); err != nil {
				return
			}
			cmd, args := "", ""
			if execs := t.Properties.Task.Actions.Exec; len(execs) > 0 {
				cmd = execs[0].Command
				args = execs[0].Arguments
			}
			runAs := t.Properties.RunAs
			if runAs == "" {
				if ps := t.Properties.Task.Principals.Principal; len(ps) > 0 {
					runAs = ps[0].UserId
				}
			}
			cs.ScheduledTasks = append(cs.ScheduledTasks, ScheduledTask{
				Name:      firstNonEmpty(t.Properties.Name, t.Name),
				Type:      elem,
				Action:    gppAction(t.Properties.Action),
				Command:   cmd,
				Arguments: args,
				RunAs:     runAs,
				CPassword: t.Properties.CPassword,
			})
		})
	}
}

// ---- Services.xml --------------------------------------------------------

type gppService struct {
	Properties struct {
		Action        string `xml:"action,attr"`
		ServiceName   string `xml:"serviceName,attr"`
		StartupType   string `xml:"startupType,attr"`
		ServiceAction string `xml:"serviceAction,attr"`
		AccountName   string `xml:"accountName,attr"`
		CPassword     string `xml:"cpassword,attr"`
	} `xml:"Properties"`
}

func parseGPPServices(data []byte, cs *ConfigSettings) {
	forEachElement(data, "NTService", func(d *xml.Decoder, start xml.StartElement) {
		var s gppService
		if err := d.DecodeElement(&s, &start); err != nil {
			return
		}
		p := s.Properties
		cs.Services = append(cs.Services, ServiceSetting{
			Source:    "gpp",
			Name:      p.ServiceName,
			StartType: p.StartupType,
			Action:    firstNonEmpty(p.ServiceAction, gppAction(p.Action)),
			Account:   p.AccountName,
			CPassword: p.CPassword,
		})
	})
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

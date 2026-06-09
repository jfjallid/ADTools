package main

import "encoding/xml"

// This file parses the remaining Group Policy Preferences item types beyond the
// groups/registry/tasks/services handled in gpp.go: ODBC data sources, mapped
// drives, file copies, shortcuts, printers and environment variables. Several
// can carry an MS14-025 cpassword; the rest matter for writable-path and
// credential-in-value analysis.

// ---- DataSources.xml -----------------------------------------------------

type gppDataSource struct {
	Name       string `xml:"name,attr"`
	Properties struct {
		Action    string `xml:"action,attr"`
		DSN       string `xml:"dsn,attr"`
		Driver    string `xml:"driver,attr"`
		Username  string `xml:"username,attr"`
		CPassword string `xml:"cpassword,attr"`
	} `xml:"Properties"`
}

func parseGPPDataSources(data []byte, cs *ConfigSettings) {
	forEachElement(data, "DataSource", func(d *xml.Decoder, start xml.StartElement) {
		var s gppDataSource
		if err := d.DecodeElement(&s, &start); err != nil {
			return
		}
		p := s.Properties
		cs.DataSources = append(cs.DataSources, DataSource{
			Name:      firstNonEmpty(p.DSN, s.Name),
			DSN:       p.DSN,
			Driver:    p.Driver,
			UserName:  p.Username,
			Action:    gppAction(p.Action),
			CPassword: p.CPassword,
		})
	})
}

// ---- Drives.xml ----------------------------------------------------------

type gppDrive struct {
	Name       string `xml:"name,attr"`
	Properties struct {
		Action    string `xml:"action,attr"`
		Letter    string `xml:"letter,attr"`
		Path      string `xml:"path,attr"`
		Username  string `xml:"userName,attr"`
		CPassword string `xml:"cpassword,attr"`
	} `xml:"Properties"`
}

func parseGPPDrives(data []byte, cs *ConfigSettings) {
	forEachElement(data, "Drive", func(d *xml.Decoder, start xml.StartElement) {
		var dr gppDrive
		if err := d.DecodeElement(&dr, &start); err != nil {
			return
		}
		p := dr.Properties
		cs.Drives = append(cs.Drives, Drive{
			Letter:    firstNonEmpty(p.Letter, dr.Name),
			Path:      p.Path,
			UserName:  p.Username,
			Action:    gppAction(p.Action),
			CPassword: p.CPassword,
		})
	})
}

// ---- Files.xml -----------------------------------------------------------

type gppFile struct {
	Properties struct {
		Action     string `xml:"action,attr"`
		FromPath   string `xml:"fromPath,attr"`
		TargetPath string `xml:"targetPath,attr"`
	} `xml:"Properties"`
}

func parseGPPFiles(data []byte, cs *ConfigSettings) {
	forEachElement(data, "File", func(d *xml.Decoder, start xml.StartElement) {
		var f gppFile
		if err := d.DecodeElement(&f, &start); err != nil {
			return
		}
		p := f.Properties
		if p.FromPath == "" && p.TargetPath == "" {
			return
		}
		cs.Files = append(cs.Files, FileDeploy{
			FromPath:   p.FromPath,
			TargetPath: p.TargetPath,
			Action:     gppAction(p.Action),
		})
	})
}

// ---- Shortcuts.xml -------------------------------------------------------

type gppShortcut struct {
	Name       string `xml:"name,attr"`
	Properties struct {
		Action     string `xml:"action,attr"`
		TargetPath string `xml:"targetPath,attr"`
		Arguments  string `xml:"arguments,attr"`
		StartIn    string `xml:"startIn,attr"`
	} `xml:"Properties"`
}

func parseGPPShortcuts(data []byte, cs *ConfigSettings) {
	forEachElement(data, "Shortcut", func(d *xml.Decoder, start xml.StartElement) {
		var s gppShortcut
		if err := d.DecodeElement(&s, &start); err != nil {
			return
		}
		p := s.Properties
		cs.Shortcuts = append(cs.Shortcuts, Shortcut{
			Name:       s.Name,
			TargetPath: p.TargetPath,
			Arguments:  p.Arguments,
			StartIn:    p.StartIn,
			Action:     gppAction(p.Action),
		})
	})
}

// ---- Printers.xml --------------------------------------------------------

// gppPrinter covers <SharedPrinter>, <PortPrinter> and <LocalPrinter>; only
// shared/port printers reference a path and may carry credentials.
type gppPrinter struct {
	Name       string `xml:"name,attr"`
	Properties struct {
		Action    string `xml:"action,attr"`
		Path      string `xml:"path,attr"`
		Username  string `xml:"username,attr"`
		CPassword string `xml:"cpassword,attr"`
	} `xml:"Properties"`
}

func parseGPPPrinters(data []byte, cs *ConfigSettings) {
	for _, elem := range []string{"SharedPrinter", "PortPrinter", "LocalPrinter"} {
		forEachElement(data, elem, func(d *xml.Decoder, start xml.StartElement) {
			var pr gppPrinter
			if err := d.DecodeElement(&pr, &start); err != nil {
				return
			}
			p := pr.Properties
			cs.Printers = append(cs.Printers, Printer{
				Name:      pr.Name,
				Path:      p.Path,
				UserName:  p.Username,
				Action:    gppAction(p.Action),
				CPassword: p.CPassword,
			})
		})
	}
}

// ---- EnvironmentVariables.xml --------------------------------------------

type gppEnvVar struct {
	Name       string `xml:"name,attr"`
	Properties struct {
		Action string `xml:"action,attr"`
		Name   string `xml:"name,attr"`
		Value  string `xml:"value,attr"`
	} `xml:"Properties"`
}

func parseGPPEnvVars(data []byte, cs *ConfigSettings) {
	forEachElement(data, "EnvironmentVariable", func(d *xml.Decoder, start xml.StartElement) {
		var e gppEnvVar
		if err := d.DecodeElement(&e, &start); err != nil {
			return
		}
		p := e.Properties
		cs.EnvVars = append(cs.EnvVars, EnvVar{
			Name:   firstNonEmpty(p.Name, e.Name),
			Value:  p.Value,
			Action: gppAction(p.Action),
		})
	})
}

package main

import (
	"fmt"
	"strings"

	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/server"
	"github.com/jfjallid/go-smb/smb/server/filevfs"
	"github.com/jfjallid/go-smb/smb/server/memvfs"
)

func (s ShareConfig) Validate() error {
	if s.Name == "" {
		return fmt.Errorf("name is required")
	}
	if strings.EqualFold(s.Name, "IPC$") {
		return fmt.Errorf("share name IPC$ is reserved")
	}
	switch strings.ToLower(s.Backend) {
	case "disk":
		if s.Path == "" {
			return fmt.Errorf("backend=disk requires path")
		}
	case "memory":
		if s.Path != "" {
			return fmt.Errorf("backend=memory does not accept path")
		}
		if s.ReadOnly {
			//TODO Why not read-only memvfs?
			return fmt.Errorf("backend=memory does not support readonly (memvfs is always writable)")
		}
	case "":
		return fmt.Errorf("backend is required (disk|memory)")
	default:
		return fmt.Errorf("unknown backend %q (want disk|memory)", s.Backend)
	}
	if s.ReadOnly && (len(s.WritableUsers) > 0 || s.AllowAnonymousWrite || s.AllowGuestWrite) {
		return fmt.Errorf("readonly is mutually exclusive with writable_users / allow_anonymous_write / allow_guest_write")
	}
	seen := map[string]bool{}
	for i, u := range s.WritableUsers {
		t := strings.TrimSpace(u)
		if t == "" {
			return fmt.Errorf("writable_users[%d] is empty", i)
		}
		k := strings.ToLower(t)
		if seen[k] {
			return fmt.Errorf("writable_users contains duplicate %q", t)
		}
		seen[k] = true
	}
	return nil
}

func buildShares(specs []ShareConfig) (map[string]server.Share, error) {
	out := make(map[string]server.Share, len(specs))
	for _, spec := range specs {
		var vfs server.VFS
		switch strings.ToLower(spec.Backend) {
		case "disk":
			fs, err := filevfs.New(filevfs.Options{Root: spec.Path, ReadOnly: spec.ReadOnly})
			if err != nil {
				return nil, fmt.Errorf("share %q filevfs(%s): %w", spec.Name, spec.Path, err)
			}
			vfs = fs
		case "memory":
			vfs = memvfs.New(memvfs.Options{})
		}
		sh := server.Share{
			Name:              spec.Name,
			Type:              smb.ShareTypeDisk,
			VFS:               vfs,
			EncryptData:       spec.Encrypt,
			AnonymousWritable: spec.AllowAnonymousWrite,
			GuestWritable:     spec.AllowGuestWrite,
		}
		if len(spec.WritableUsers) > 0 {
			m := make(map[string]bool, len(spec.WritableUsers))
			for _, u := range spec.WritableUsers {
				m[strings.ToLower(strings.TrimSpace(u))] = true
			}
			sh.WritableUsers = m
		}
		out[strings.ToLower(spec.Name)] = sh
		log.Debugf("Creating share: %+v\n", sh)
	}
	return out, nil
}

// parseShareSpec parses a CLI --share value: "name=Public,backend=disk,path=/srv,readonly=true,encrypt=false".
func parseShareSpec(s string) (ShareConfig, error) {
	var sc ShareConfig
	// Allow writes unless explicitly denied
	sc.AllowAnonymousWrite = true
	sc.AllowGuestWrite = true
	kv, err := parseKVList(s)
	if err != nil {
		return sc, err
	}
	for k, v := range kv {
		switch k {
		case "name":
			sc.Name = v
		case "backend":
			sc.Backend = v
		case "path":
			sc.Path = v
		case "readonly":
			b, err := parseBool(v)
			if err != nil {
				return sc, fmt.Errorf("readonly: %w", err)
			}
			sc.ReadOnly = b
		case "encrypt":
			b, err := parseBool(v)
			if err != nil {
				return sc, fmt.Errorf("encrypt: %w", err)
			}
			sc.Encrypt = b
		case "writable_users":
			sc.WritableUsers = nil
			for _, u := range strings.Split(v, "|") {
				u = strings.TrimSpace(u)
				if u == "" {
					continue
				}
				sc.WritableUsers = append(sc.WritableUsers, u)
			}
		case "allow_anonymous_write":
			b, err := parseBool(v)
			if err != nil {
				return sc, fmt.Errorf("allow_anonymous_write: %w", err)
			}
			sc.AllowAnonymousWrite = b
		case "allow_guest_write":
			b, err := parseBool(v)
			if err != nil {
				return sc, fmt.Errorf("allow_guest_write: %w", err)
			}
			sc.AllowGuestWrite = b
		default:
			return sc, fmt.Errorf("unknown share key %q", k)
		}
	}
	if sc.ReadOnly {
		sc.AllowAnonymousWrite = false
		sc.AllowGuestWrite = false
	}
	if sc.Backend == "" {
		log.Noticef("No backend specified for share %s, falling back to 'disk'\n", sc.Name)
		sc.Backend = "disk"
	}
	if sc.Backend == "disk" && sc.Path == "" {
		sc.Path = "."
		log.Warningf("share %s created without a specified path, using current directory instead\n", sc.Name)
	}
	return sc, nil
}

func parseKVList(s string) (map[string]string, error) {
	out := map[string]string{}
	for _, piece := range strings.Split(s, ",") {
		piece = strings.TrimSpace(piece)
		if piece == "" {
			continue
		}
		eq := strings.IndexByte(piece, '=')
		if eq < 0 {
			return nil, fmt.Errorf("missing = in %q", piece)
		}
		k := strings.TrimSpace(piece[:eq])
		v := strings.TrimSpace(piece[eq+1:])
		if k == "" {
			return nil, fmt.Errorf("empty key in %q", piece)
		}
		if _, dup := out[k]; dup {
			return nil, fmt.Errorf("duplicate key %q", k)
		}
		out[k] = v
	}
	return out, nil
}

func parseBool(s string) (bool, error) {
	switch strings.ToLower(s) {
	case "true", "1", "yes", "y", "on":
		return true, nil
	case "false", "0", "no", "n", "off", "":
		return false, nil
	}
	return false, fmt.Errorf("not a boolean: %q", s)
}

func dialectFromString(s string) (uint16, error) {
	switch s {
	case "2.0.2":
		return smb.DialectSmb_2_0_2, nil
	case "2.1":
		return smb.DialectSmb_2_1, nil
	case "3.0":
		return smb.DialectSmb_3_0, nil
	case "3.0.2":
		return smb.DialectSmb_3_0_2, nil
	case "3.1.1":
		return smb.DialectSmb_3_1_1, nil
	case "":
		return 0, fmt.Errorf("empty dialect string")
	default:
		return 0, fmt.Errorf("unknown dialect %q (want 2.0.2|2.1|3.0|3.0.2|3.1.1)", s)
	}
}

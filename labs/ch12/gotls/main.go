// Lab 12.1 -- a minimal TLS 1.3 server and client in Go's standard library, for the interop matrix.
// Go 1.24+ enables X25519MLKEM768 by default; -groups selects CurvePreferences by name.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
)

var groupNames = map[string]tls.CurveID{
	"X25519":          tls.X25519,
	"secp256r1":       tls.CurveP256,
	"secp384r1":       tls.CurveP384,
	"X25519MLKEM768":  tls.X25519MLKEM768,
}

func parseGroups(s string) ([]tls.CurveID, error) {
	var out []tls.CurveID
	for _, n := range strings.Split(s, ":") {
		g, ok := groupNames[n]
		if !ok {
			return nil, fmt.Errorf("unsupported group %q in this Go", n)
		}
		out = append(out, g)
	}
	return out, nil
}

func main() {
	mode := flag.String("mode", "client", "server|client")
	addr := flag.String("addr", "127.0.0.1:4470", "listen/connect address")
	groups := flag.String("groups", "X25519MLKEM768:X25519", "colon-separated CurvePreferences")
	cert := flag.String("cert", "", "server certificate PEM")
	key := flag.String("key", "", "server key PEM")
	ca := flag.String("ca", "", "CA PEM the client trusts")
	flag.Parse()
	prefs, err := parseGroups(*groups)
	if err != nil {
		fmt.Println("UNSUPPORTED", err)
		os.Exit(3)
	}
	if *mode == "server" {
		c, err := tls.LoadX509KeyPair(*cert, *key)
		if err != nil {
			panic(err)
		}
		cfg := &tls.Config{Certificates: []tls.Certificate{c}, MinVersion: tls.VersionTLS13, CurvePreferences: prefs}
		ln, err := tls.Listen("tcp", *addr, cfg)
		if err != nil {
			panic(err)
		}
		conn, err := ln.Accept()
		if err != nil {
			panic(err)
		}
		tc := conn.(*tls.Conn)
		if err := tc.Handshake(); err != nil {
			fmt.Println("FAIL", err)
			os.Exit(1)
		}
		st := tc.ConnectionState()
		fmt.Printf("OK version=0x%04x\n", st.Version) // Go 1.24 does not expose the negotiated group; the observer reads it from the wire
		io.WriteString(tc, "hello from go\n")
		tc.Close()
		return
	}
	pool := x509.NewCertPool()
	if *ca != "" {
		pem, err := os.ReadFile(*ca)
		if err != nil {
			panic(err)
		}
		pool.AppendCertsFromPEM(pem)
	}
	cfg := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13, CurvePreferences: prefs, ServerName: "api.example.test"}
	d := net.Dialer{}
	raw, err := d.Dial("tcp", *addr)
	if err != nil {
		fmt.Println("FAIL", err)
		os.Exit(1)
	}
	tc := tls.Client(raw, cfg)
	if err := tc.Handshake(); err != nil {
		fmt.Println("FAIL", err)
		os.Exit(1)
	}
	st := tc.ConnectionState()
	fmt.Printf("OK version=0x%04x\n", st.Version)
	tc.Close()
}

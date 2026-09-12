package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"log"
	"net/http"
)

func main() {
	// Per-instance identity key for mTLS to the backend.
	_, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	cfg := &tls.Config{
		MinVersion:       tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{tls.CurveP256, tls.X25519},
	}
	srv := &http.Server{Addr: ":8443", TLSConfig: cfg}
	log.Fatal(srv.ListenAndServeTLS("certs/server.crt", "certs/server.key"))
}

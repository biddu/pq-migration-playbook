# payments-gateway (sample service for Lab 3.1)

A deliberately small, deliberately old-fashioned service: a Python API that
issues RS256 JWTs and wraps data keys with RSA-OAEP, a Go edge gateway that
terminates TLS with ECDSA P-256, an nginx front end, an SSH bastion config,
and a self-signed RSA certificate. Every cryptographic choice in it is one
the scanner in Lab 3.1 should find.

#!/usr/bin/env sh
# Start Pebble (Let's Encrypt's ACME test server) for Lab 7.3. Run from the repository root.
# Install: go install github.com/letsencrypt/pebble/v2/cmd/pebble@latest
# PEBBLE_VA_NOSLEEP=1 removes Pebble's deliberate validation delays; PEBBLE_WFE_NONCEREJECT=0 stops its
# random bad-nonce injection, a test feature this lab does not exercise.
# the default profile's validityPeriod in the config is 47 days in seconds (47 * 86400 = 4,060,800).
# Set PEBBLE_DNS=host:port to point validation at your own resolver; by default the system resolver is used,
# which is why the lab's hostname is "localhost".
export PEBBLE_VA_NOSLEEP=1 PEBBLE_WFE_NONCEREJECT=0
if [ -n "$PEBBLE_DNS" ]; then set -- -dnsserver "$PEBBLE_DNS"; fi
exec "${PEBBLE_BIN:-$HOME/go/bin/pebble}" -config labs/ch07/pebble/pebble-config.json "$@"

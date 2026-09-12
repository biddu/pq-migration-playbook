#!/usr/bin/env sh
# Initialise the lab's SoftHSM token (no PQ mechanisms; that is the point of the audit). Run from the repo root.
# apt-get install softhsm2   |   pip install python-pkcs11
export SOFTHSM2_CONF="$(pwd)/labs/ch10/softhsm/softhsm2.conf"
mkdir -p labs/ch10/softhsm/tokens
printf 'directories.tokendir = %s/labs/ch10/softhsm/tokens\nobjectstore.backend = file\nlog.level = ERROR\n' "$(pwd)" > "$SOFTHSM2_CONF"
softhsm2-util --init-token --free --label pqm-lab --pin 1234 --so-pin 12345678
echo "export SOFTHSM2_CONF=$SOFTHSM2_CONF"

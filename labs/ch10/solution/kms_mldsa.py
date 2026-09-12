"""Lab 10.3 (optional, cloud) -- create and use an ML-DSA key in AWS KMS, or show exactly what
the calls would be without an account.

AWS KMS has offered ML-DSA keys (KeySpec ML_DSA_44 / ML_DSA_65 / ML_DSA_87) as generally
available since June 2025. Two API details matter for a migration and are the point of this
lab: the private key never leaves KMS and cannot be exported, and Sign() accepts either the
message itself (MessageType RAW, at most 4 KB) or the 64-byte external mu (MessageType
EXTERNAL_MU) that the caller computes per FIPS 204 section 6.2 with the public key. Anything
larger than 4 KB is therefore signed by the external-mu pattern from hsmplan.py, and the
public key is fetched once with GetPublicKey.

With credentials (boto3 configured), --live creates a key, signs a file by external mu,
verifies locally with `cryptography`, and schedules the key for deletion (7 days minimum),
noting the per-key monthly charge and the per-request charges in the KMS price list, which
you should read before running. Without --live the tool prints the request bodies.

Tested with: Python 3.12, cryptography 50.0; the --live path was exercised against the API
shapes in the AWS documentation and needs your own account to run.
"""
from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import mldsa
from cryptography.hazmat.primitives import serialization


def requests_for(spec: str, message: bytes) -> list[dict]:
    """The KMS API calls a migration script makes, as JSON, so they can be reviewed without an account."""
    return [
        {"CreateKey": {"KeySpec": spec, "KeyUsage": "SIGN_VERIFY", "Origin": "AWS_KMS",
                       "Description": "PQM lab ML-DSA signing key", "Tags": [{"TagKey": "pqm-lab", "TagValue": "ch10"}]}},
        {"GetPublicKey": {"KeyId": "<KeyId from CreateKey>"}},
        {"Sign": {"KeyId": "<KeyId>", "MessageType": "RAW" if len(message) <= 4096 else "EXTERNAL_MU",
                  "Message": "<message bytes>" if len(message) <= 4096 else "<64-byte mu computed on the host with MLDSAMuHasher(public key)>",
                  "SigningAlgorithm": "ML_DSA_SHAKE_256"}},
        {"ScheduleKeyDeletion": {"KeyId": "<KeyId>", "PendingWindowInDays": 7}},
    ]


def live(spec: str, message: bytes) -> dict:
    import boto3
    kms = boto3.client("kms")
    key = kms.create_key(KeySpec=spec, KeyUsage="SIGN_VERIFY", Description="PQM lab ML-DSA signing key",
                         Tags=[{"TagKey": "pqm-lab", "TagValue": "ch10"}])["KeyMetadata"]
    kid = key["KeyId"]
    try:
        der = kms.get_public_key(KeyId=kid)["PublicKey"]
        pub = serialization.load_der_public_key(der)                  # SubjectPublicKeyInfo with the RFC 9881 OID
        if len(message) <= 4096:
            sig = kms.sign(KeyId=kid, Message=message, MessageType="RAW", SigningAlgorithm="ML_DSA_SHAKE_256")["Signature"]
        else:
            h = mldsa.MLDSAMuHasher(pub); h.update(message); mu = h.finalize()
            sig = kms.sign(KeyId=kid, Message=mu, MessageType="EXTERNAL_MU", SigningAlgorithm="ML_DSA_SHAKE_256")["Signature"]
        pub.verify(sig, message)
        return {"KeyId": kid, "spec": spec, "message_bytes": len(message), "signature_bytes": len(sig), "verified_locally": True}
    finally:
        kms.schedule_key_deletion(KeyId=kid, PendingWindowInDays=7)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="ML-DSA in AWS KMS: dry-run request shapes, or --live with your own account.")
    p.add_argument("--spec", default="ML_DSA_65", choices=["ML_DSA_44", "ML_DSA_65", "ML_DSA_87"])
    p.add_argument("--file", help="artefact to sign (default: 1 MiB of zeros)")
    p.add_argument("--live", action="store_true")
    a = p.parse_args(argv)
    message = Path(a.file).read_bytes() if a.file else bytes(1 << 20)
    if a.live:
        print(json.dumps(live(a.spec, message), indent=2))
        return 0
    print(f"dry run: {a.spec}, artefact {len(message):,} B -> {'RAW' if len(message) <= 4096 else 'EXTERNAL_MU'} path\n")
    for r in requests_for(a.spec, message):
        print(json.dumps(r, indent=2))
    print("\nRead the KMS price list for the per-key monthly charge and per-request charges before running --live;"
          " the key is scheduled for deletion (7-day minimum) at the end of the run.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

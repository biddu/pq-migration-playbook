"""Outbound calls to the card network."""
import ssl

import requests

CTX = ssl.create_default_context()
CTX.minimum_version = ssl.TLSVersion.TLSv1_2
CTX.set_ciphers("ECDHE+AESGCM")


def post_authorisation(payload: dict) -> dict:
    return requests.post("https://acquirer.example.net/auth", json=payload, timeout=5).json()

# Labs 6.1–6.2 — SSH key exchange, measured; post-quantum PSKs for WireGuard

**Lab 6.1** is an SSH observer and fleet auditor. In relay mode it parses the
plaintext part of the SSH transport (identification, both KEXINITs, the key
exchange messages) and reports the negotiated method and the byte sizes. In audit
mode it connects to each host in a list, reads the server's KEXINIT and reports
whether a post-quantum method is offered and first, without logging in.
**Lab 6.2** derives WireGuard pre-shared keys from an ML-KEM-768 encapsulation and
prints the `wg set` commands (dry-run works without WireGuard).

| File | What it is |
|---|---|
| `solution/sshobserve.py` | Observer + auditor (reference). `starter_sshobserve.py` is your file. |
| `solution/kexlab.py` | Runs six sshd/ssh scenarios through the observer; writes `results/kex.json` and `fixtures/`. |
| `solution/wgpsk.py` | ML-KEM-derived WireGuard PSK provisioning. |
| `sshd/` | Throwaway sshd config, host keys and a client key for the lab (do not reuse). |
| `fixtures/` | Raw byte streams for six handshakes (offline tests). |

```bash
# OpenSSH 10+ (any 9.9+ has mlkem768x25519-sha256; 10.0 made it the default)
export OPENSSH_PREFIX=/opt/openssh10
pytest labs/ch06/tests
python labs/ch06/solution/kexlab.py
printf 'bastion.example:22\n127.0.0.1:2222\n' > hosts.txt
python labs/ch06/solution/sshobserve.py audit hosts.txt
# Lab 6.2, dry run
python labs/ch06/solution/wgpsk.py keygen --out /tmp/resp.key
python labs/ch06/solution/wgpsk.py encaps --responder-ek <EK> --wg-pub-self <A> --wg-pub-peer <B> --dry-run
python labs/ch06/solution/wgpsk.py decaps --key /tmp/resp.key --ciphertext <CT> --wg-pub-self <B> --wg-pub-peer <A> --dry-run
```

Tested with: Python 3.12, OpenSSH 10.1p1, cryptography 50.0, pytest 9.

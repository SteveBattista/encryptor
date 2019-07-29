[![Safety Dance](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)

Does not test nonce advance as we want to try an unlimited number of attempts. Uses less_safe_key in aead.

Built with untrusted = "0.6.2"  Using "0.7.0" causes errors
Built with ring = "0.16.5"

PBKDF2 function lenght is capped at 100 (remainder of bytelength)
Most keys are hashes of the byte input
Most salts are hashes of the byte input or key.

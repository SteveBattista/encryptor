[![Safety Dance](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)
<BR>
Does not test nonce advance as we want to try an unlimited number of attempts. Uses less_safe_key in aead.
<BR>
Built with untrusted = "0.6.2"  Using "0.7.0" causes errors<BR>
Built with ring = "0.16.5"<BR>


Not testing  the wiring of PKS8 files to disk. Just keeping them in memory.<BR>
In aead nonce is first 12 bytes of the key.<BR>

zero legnth input can cause crashes. (PBKDF2 random1 or random2). There needs to also be a check for length of output<BR>

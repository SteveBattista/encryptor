[![Safety Dance](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)
<BR>
Built with:<BR>
Built with untrusted = "0.6.2"  Using "0.7.0" causes errors<BR>
Built with ring = "0.16.5"<BR>


Not testing:<BR>
The writing of PKS8 files to disk. Just keeping them in memory.<BR>
Does not test nonce advance as we want to try an unlimited number of attempts. Uses less_safe_key in aead.<BR>

Might Impact Outcome:<BR>
In aead nonce is first 12 bytes of the key.<BR>

zero length in random1 or random2 can cause crashes. (PBKDF2 needs non zero). <BR>


TODO<BR>
1. RSA signatures <BR>
2. Make a lot more constants <BR>
3. Clean up println! statements <BR>

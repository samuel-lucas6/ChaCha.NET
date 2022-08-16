[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/samuel-lucas6/ChaCha.NET/blob/main/LICENSE)

# ChaCha.NET

A .NET implementation of [ChaCha8](https://eprint.iacr.org/2019/1492.pdf), [ChaCha12](https://competitions.cr.yp.to/estream.html), and [ChaCha20](https://www.rfc-editor.org/rfc/rfc8439).

> **Warning**
> 
> - You'd be better off using ChaCha20 from [libsodium](https://www.geralt.xyz/advanced/chacha20).
> - The nonce **MUST NOT** be repeated or reused with the same key.
> - Do **NOT** touch the counter unless you know how ChaCha works internally.
> - I do **NOT** recommend ChaCha8; ChaCha20 offers a much safer security margin.

# AES

A minimal C++ library implementing AES-128 and AES-256 encryption, built strictly to FIPS 197.

## Overview

My personal take on the AES (Advanced Encryption Standard) algorithm, implemented strictly following [FIPS 197](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf). Designed with a focus on simplicity, clean API, no dependencies, single include.

## Features

Currently implements **AES-ECB** mode only. ECB (Electronic Codebook) is the simplest block cipher mode, each 16-byte block is encrypted independently, which makes it fast, but also means identical plaintext blocks produce identical ciphertext blocks. Read more about the vulnerability [here](https://crim.blog/posts/ecb-attack).

## Getting Started

### Prerequisites

- Visual Studio 2022 (or later with C++17 support)
- Platform Toolset v143 or later

### Building

1. Clone the repository:
```bash
git clone https://github.com/NtProtectVirtualMemory/AES.git
```

2. Add the `crypto` folder to your build system or Visual Studio project.

### Basic Usage

```cpp
#include "crypto/AES.h"

int main()
{
    // Column Major
    uint8_t state[16] = 
    {
    	0x32, 0x43, 0xf6, 0xa8,
    	0x88, 0x5a, 0x30, 0x8d,
    	0x31, 0x31, 0x98, 0xa2,
    	0xe0, 0x37, 0x07, 0x34
    };

    uint8_t key[16] = 
    {
        0x2b, 0x7e, 0x15, 0x16,
        0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88,
        0x09, 0xcf, 0x4f, 0x3c
    };

    AES::Context ctx{ 0 };
    AES::init_context(ctx, key, AES_128);

    AES::encrypt_block(state, ctx);
    AES::decrypt_block(state, ctx);

}

```

## How to contribute

1. If you're fixing a bug or adding a feature, please **open an issue first** (unless it's a very obvious typo/doc fix)
2. Fork the repository and create your branch from `master`
3. Make sure the code follows the current style:
   - Use C++20 features when it improves readability/safety
   - Use `snake_case` everywhere
   - Keep the public API clean & minimal
4. Make small, focused pull requests with clear titles & description

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE.txt) file for details.

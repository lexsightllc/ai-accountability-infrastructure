<!-- SPDX-License-Identifier: MPL-2.0 -->

# Keys Directory

This directory contains cryptographic keys used by the AI Trust system.

## Security Notice

Do not commit actual private keys to version control. This directory is included in `.gitignore` to prevent accidental commits of sensitive information.

## Usage

1. Place your public/private key pairs in this directory
2. Use the [ai_trust](cci:7://file:///Volumes/Sem%20T%C3%ADtulo/AI-Accountability-Infrastructure/Volumes/Sem%20T%C3%ADtulo/AI-Accountability-Infrastructure/ai_trust:0:0-0:0) CLI or API to manage keys
3. Reference keys in your configuration using relative paths

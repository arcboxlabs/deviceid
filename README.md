# @deviceid/core

A device ID that can't be faked: the fingerprint of a key your hardware holds.

Readable machine identifiers (serial numbers, `IOPlatformUUID`, `/etc/machine-id`)
are spoofable — a server can never verify that a client actually read them from
hardware. `deviceid` inverts the model: it generates a P-256 keypair inside the
machine's security hardware and derives the device ID from the public key.
Claiming the ID means signing with the key; cloning the ID means extracting a
private key that physically cannot leave the chip.

| Platform | Backend | `protection` |
| --- | --- | --- |
| macOS | Secure Enclave (CryptoKit, no entitlements needed) | `hardware` |
| Windows | TPM 2.0 (CNG platform crypto provider) | `hardware` |
| WSL2 | Bridge to the host Windows TPM | `hardware` |
| Linux | Keyring-encrypted key | `software` |

Built on [godaddy/hardware-enclave](https://github.com/godaddy/hardware-enclave),
exposed to Node.js via [napi-rs](https://napi.rs) prebuilt binaries.

## Usage

```ts
import { ensureDeviceId } from '@deviceid/core';

const device = ensureDeviceId({ dir: '~/.myapp/keys' });

device.id;            // 'SHA256:Jgr0OcWi…' — stable fingerprint of the public key
device.publicKeyPem;  // SPKI PEM, enroll this with your server
device.protection;    // 'hardware' | 'software'
device.sign(payload); // base64url P1363 ECDSA signature (SHA-256)
```

Signatures verify with WebCrypto as-is:

```ts
const key = await crypto.subtle.importKey('spki', spkiDer, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
const ok = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, signature, payload);
```

## Development

Rust comes project-scoped via [devenv](https://devenv.sh); macOS additionally
needs Xcode Command Line Tools for the Swift bridge.

```sh
devenv shell
pnpm build   # napi build --platform --release
pnpm test    # exercises the real hardware backend
```

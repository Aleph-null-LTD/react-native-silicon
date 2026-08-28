# react-native-silicon 🔐
Hardware-backed cryptography module for React Native. Currently under active development by Aleph-null Ltd.

[![npm version](https://img.shields.io/npm/v/react-native-silicon.svg?style=flat)](https://www.npmjs.com/package/react-native-silicon)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-ios%20%7C%20android-blue.svg)]()
[![GitHub Repository](https://img.shields.io/badge/GitHub-Repository-black?logo=github)](https://github.com/Aleph-null-LTD/react-native-silicon)

**react-native-silicon** provides a comprehensive, modern API for hardware-backed cryptography in React Native and Expo. 

> **Development Status:**
> This project is currently in early alpha and is **NOT** in a production-ready state. Testing is on-going, and APIs are subject to breaking changes. Use in production environments is highly discouraged at this time.

## Features

* **Zero Dependencies:** Ultra-lean footprint.
* **TypeScript-First DX:** Full autocomplete and type safety.
* **Hardware-backed:** Direct integration with StrongBox/TEE (Android) and Secure Enclave (iOS).
* **Silent Signing:** Sign payloads without unnecessary biometric interruptions for background tasks.
* **Modern Standards:** First-class support for JOSE and OAuth2.0 (OAuth2.1 pending its official release) compliance.
* **Attestation:** Hardware attestation to verify key integrity on the backend.
* **Modern Architecture:** Built from the ground up using the Expo Modules API.

## Roadmap & Current Status

Because this library is in active development, some features are still being finalized. Here is the current progress:

**Core Cryptography**
- 🧪 Key Generation (RSA, EC)
- 🧪 Hardware persistence (Keystore / Secure Enclave)
- 🚧 Software key fallback
- 🧪 Signing and Verification
- ⏳ Encryption and Decryption (Planned)
- 🧪 Secure random bytes generation
- ⏳ ECDH (Elliptic Curve Diffie-Hellman)
- ⏳ Passkey (FIDO2/WebAuthn) Abstractions
- ⏳ Key Wrapping

**Biometrics & Security**
- 🧪 Biometrics integration
- 🧪 Key/Hardware Attestation

**Standards (JOSE / OAuth)**
- 🧪 JWK Export
- 🧪 JWT Signing
- 🧪 DPoP Proof Generation

*(Key: ✅ Complete & Tested, 🧪 Implemented (Testing Ongoing), 🚧 Under Active Development, ⏳ Planned)*

---

## Installation

Install the package using your preferred package manager:

```bash
npm install react-native-silicon
# or
yarn add react-native-silicon
# or
pnpm add react-native-silicon
```

### Expo Projects Setup
For expo projects follow these steps, for bare React Native projects, skip to the section below. 

Add the plugin to your app.json file:
```json
{
  "expo": {
    "plugins": [
      [
        "react-native-silicon",
        {
          "faceIDPermission": "Allow $(PRODUCT_NAME) to use Face ID for secure cryptographic keys."
        }
      ]
    ]
  }
}
```

Regenerate your native folders to apply the changes cleanly:
```bash
npx expo prebuild --clean
```

### Bare React Native Projects Setup
Your project does NOT have to be an Expo app; however, the core expo package is required as the native bridge for this module.

1. Install Expo infrastructure:
```bash
npm install expo
```

2. Run the auto-installer: 
This automatically modifies your existing `Podfile`, `build.gradle`, and `MainApplication` files to support Expo modules:
```bash
npx install-expo-modules
```

3. Configure Native Permissions:
If using the biometrics features, update your `Info.plist` file for iOS:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <!-- ... other existing keys ... -->
  
  <!-- ADD THESE TWO LINES -->
  <key>NSFaceIDUsageDescription</key>
  <string>Allow $(PRODUCT_NAME) to use Face ID to securely generate and access cryptographic keys.</string>
</dict>
</plist>
```
and your `AndroidManifest.xml` file for Android (above the `<application>` tag):
```xml
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  
  <!-- ADD THIS LINE -->
  <uses-permission android:name="android.permission.USE_BIOMETRIC" />
  
  <application ...>
    ...
  </application>
</manifest>
```

4. Install iOS Pods:
For iOS builds, manually install the pods first:
```bash
cd ios && pod install
```

---

## Usage

### Keys & Persistence
Keys will persist in the Keystore (Android) or Keychain (iOS) until explicitly deleted. It is recommended that you check for the existence of a key before attempting to generate a new one.

The iOS Secure Enclave **ONLY** allows EC P-256 keys. All other keys must be generated as software keys and cannot be hardware backed. Android is much more relaxed, and allows many different key algorithms to be stored in TEE/StrongBox.

### Error Handling
Hardware cryptography can fail for native reasons (e.g., user cancels FaceID, Secure Enclave is locked). Therefore you should always wrap your calls in a try/catch block. 

All errors thrown will be an instance of `SiliconError`, and will have a `SiliconErrorCode` as the `code` property:
```ts
import { generateKey, SiliconError, SiliconErrorCode } from 'react-native-silicon';

try {
    await generateKey('my.secure.key');
} catch (error) {
    if (error instanceof SiliconError) {
        switch (error.code) {
            case SiliconErrorCode.HARDWARE_NOT_AVAILABLE:
                console.error("Failed to generate hardware key:", error.message);
                break;
            // Handle other error codes...
        }
    }
    // Handle other errors...
}
```

### Simple Usage

We provide sensible defaults for a clean developer experience. The API can be as simple as:
```ts
import { generateKey, sign } from 'react-native-silicon';

const keyAlias = 'myapp.some.alias';
const data = "some_random_data_string";

// Generate a hardware-backed key
await generateKey(keyAlias);

// Sign the data
const signature = await sign(keyAlias, data);
```
*Note: We recommend explicitly defining configuration values for readability in larger projects. Check the inline JSDoc comments via your IDE for all available default values.*

### API

Currently available API functions. Rely on your IDE's TypeScript autocomplete for exact parameters and return types.

**Key Management:**
* **`generateKey`** - Creates a new cryptographic key.
* **`deleteKey`** - Permanently deletes a key.
* **`deleteAllKeys`** - Permanently deletes all keys with the given prefix, or all keys if no prefix is provided. **USE WITH CAUTION**
* **`keyExists`** - Checks if a key currently exists with the given alias.
* **`listKeys`** - Lists all keys with a given prefix, or all keys if no prefix is provided.
* **`validateKey`** - Validates a key, determining if it is in a usable state.
* **`getPubKey`** - Gets the public key from an asymmetric keypair.
* **`attestKey`** - Performs an attestation of a key.
* **`getKeyInfo`** - Returns info about the key specified with the given alias.

**Device:**
* **`getCapabilities`** - Returns an object containing the hardware capabilities of the device.

**Operations:**
* **`sign`** - Performs a sign operation on the given data and returns the signature.
* **`verify`** - Performs a verify operation on the given data against the given signature.
* **`generateSecureRandomBytes`** - Generates random bytes securely using dedicated hardware.

**JOSE (JSON Object Signing and Encryption):**
We provide abstractions to make strict JOSE (JSON Object Signing and Encryption) implementations as simple as possible.
* **`signJwt`** - Constructs and signs a JSON Web Token (JWT) using the key with the given alias.
* **`getJwk`** - Gets a JSON Web Key (JWK) from the key with the given alias.

**OAuth2.0:**
We provide abstractions to make strict OAuth2.0 implementations as simple as possible.
* **`generateDpopProof`** - Constructs and signs a OAuth2.0 compliant DPoP proof JWT using the key with the given alias.

---

## Helpful Resources
* JWT validation/verification - https://www.jwt.io/

## License
MIT License. Copyright (c) 2026 Aleph-null Ltd. See `LICENSE` for more information.

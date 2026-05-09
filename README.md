# react-native-silicon 🔐
Hardware-backed cryptography module for React Native. Currently under active development by Aleph-Null Ltd.

[![npm version](https://img.shields.io/npm/v/react-native-silicon.svg?style=flat)](https://www.npmjs.com/package/react-native-silicon)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-ios%20%7C%20android-lightgrey.svg)]()

**react-native-silicon** provides a comprehensive, modern API for hardware-backed cryptography in React Native and Expo. 

## Development Status

This project is currently a Work in Progress. 

## Key Objectives

* Direct hardware integration with the Secure Enclave (iOS) and StrongBox/TEE (Android).
* Silent signing capabilities to avoid unnecessary biometric interruptions for background tasks.
* First-class support for DPoP and OAuth 2.1 compliance.
* Hardware attestation to verify key integrity on the backend.
* Minimalist, modern API design using the Expo Modules architecture.

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
---

## License
MIT License. Copyright (c) 2026 Aleph-null Ltd. See `LICENSE` for more information.

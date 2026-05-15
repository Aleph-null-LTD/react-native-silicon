# react-native-silicon 🔐
Hardware-backed cryptography module for React Native. Currently under active development by Aleph-null Ltd.

[![npm version](https://img.shields.io/npm/v/react-native-silicon.svg?style=flat)](https://www.npmjs.com/package/react-native-silicon)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-ios%20%7C%20android-blue.svg)]()
[![GitHub Repository](https://img.shields.io/badge/GitHub-Repository-black?logo=github)](https://github.com/Aleph-null-LTD/react-native-silicon)

**react-native-silicon** provides a comprehensive, modern API for hardware-backed cryptography in React Native and Expo. 

## Development Status

This project is currently a Work in Progress, and is not currently in a working state. 
We hope to have a working pre-release version up and running within the next couple of weeks (as of 10th May 2026)

## Features

* Zero Dependencies: Ultra-lean footprint
* TypeScript-First DX
* Hardware-backed: Direct integration with StrongBox/TEE (Android) and the Secure Enclave (iOS)
* Silent signing capabilities to avoid unnecessary biometric interruptions for background tasks
* First-class support for DPoP and OAuth 2.1 compliance
* Hardware attestation to verify key integrity on the backend
* Minimalist, modern API design using the Expo Modules architecture

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

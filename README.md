# tpmman

`tpmman` is a **PKCS#11** wrapper and manager that provides a unified interface for **TPM**-based and other PKCS#11 backends. 
It allows for simplified configuration and management of cryptographic tokens.

### Use cases

- _Automated PIN Management for Headless Environments_. Standard **PKCS#11** modules often require interactive PIN entry.
  In _CI/CD_ pipelines, automated servers, or background daemons, this is impossible. **tpmman** reads the **PIN** from a secure _YAML_ config
  and performs the _C_Login_ automatically, allowing headless applications to use hardware tokens without human intervention.


- _Unified Interface for Multiple Tokens_. An application might only support loading a single **PKCS#11** module, but you may have keys spread across a **TPM**, a **YubiKey**, and a software **HSM**.
  You use **tpmman** as the primary module. By swapping the backend path in the config file, you can point the application to different hardware without changing the application's internal settings.


- _Transparent Development & Testing_. Developers often need to write code that will eventually run on expensive _Hardware Security Modules_ (HSMs) but want to develop using local software.
  A developer uses **tpmman** with **SoftHSM2** software during development. When moving to production, they simply update the config.yml to point to the real **OpenSC** or **Hardware HSM** backend. No code changes are required.


- _Simplified Token Discovery (Label Mapping)_. In systems with many slots and readers, finding the right token can be difficult for applications.
  **tpmman** allows you to map specific token Labels to internal configurations. When an application asks for a slot list,
  **tpmman** can ensure that only the "mapped" and recognized tokens are presented and correctly initialized.


### Features

- **PKCS#11** thin **wrapper**: Implements PKCS#11 interface that delegates calls to a configurable backend library.
- **YAML Configuration**: Easy setup for backend paths, debug modes, and token mappings via `configs/config.yml`.
- **Token Management**: Automated mapping of saved tokens based on labels, including user PIN management.
- **Integrated Logging**:  Logging using the Poco library.

### Testing (with OpenSC integration)

> **Note**: This project has been tested with OpenSC on macOS.

[OpenSC](https://github.com/OpenSC/OpenSC) is an open-source project that provides libraries and utilities to work with smart cards and other cryptographic tokens. It implements the PKCS#11 API, making it a perfect backend for `tpmman` when working with hardware tokens.

_Installing OpenSC_

- darwin:
```bash
brew install opensc
```
- linux (**Ubuntu / Debian**):
```bash
  sudo apt update
  sudo apt install opensc pcscd
```

### Compatible Backends

`tpmman` is a generic wrapper and can be used with any library that implements the PKCS#11 (Cryptoki) standard. Common backends include:

- **libykcs11**: Yubico's library for YubiKey PIV support.
- **SoftHSM2**: Software-based implementation of a cryptographic token.
- **tpm2-pkcs11**: Interface to Hardware TPM 2.0 chips.
- **Hardware/Cloud HSMs**: Enterprise solutions from AWS, Azure

*Note: While many backends are compatible, `tpmman` currently focuses on a subset of the PKCS#11 API (primarily Session Management, Object Searching, and Signing).*

### Prerequisites

- CMake 4.0+
- [yaml-cpp](https://github.com/jbeder/yaml-cpp)
- [Poco Project](https://pocoproject.org/) (Foundation)
- **OpenSC** (optional, but recommended as a PKCS#11 backend)


### Building

```bash
mkdir build
cd build
cmake ..
make
```

### Usage

1. Configure your backend library and tokens in `configs/config.yml`.
2. Use the generated `libtpmman.dylib` or `libtpmman.so` as a PKCS#11 module in your application.
3. Test the setup using the provided script:
   ```bash
   python scripts/tpmman.py
   ```

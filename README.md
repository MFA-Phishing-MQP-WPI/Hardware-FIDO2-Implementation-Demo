# FIDO2 Authentication Demo Using YubiKey

## Table of Contents
1. [Overview](#overview)
2. [How to Run the Demo](#how-to-run-the-demo)
   - [Prerequisites](#prerequisites)
   - [Required Packages](#required-packages)
   - [Steps to Run](#steps-to-run)
3. [FIDO2 MFA Usage Demo](#FIDO2-MFA-Usage-Demo)
4. [Important Classes and Their Functions](#important-classes-and-their-functions)
   - [UserInterface](#1-userinterface)
   - [Client](#2-client)
   - [RelyingParty](#3-relyingparty)
   - [YubiKey](#4-yubikey)
   - [SessionToken](#5-sessiontoken)
   - [OperatingSystem](#6-operatingsystem)
5. [How the Demo Works](#how-the-demo-works)
6. [Visualizing Logs](#visualizing-logs)
7. [Future Work](#future-work)
8. [Troubleshooting](#troubleshooting)
9. [Already Implemented](#already-implemented)
10. [Resources](#Resources)

## Overview

This repository contains a Python-based demo that simulates FIDO2 authentication using a YubiKey-like hardware security token. The demo showcases the interaction between a client (browser), a relying party (web service), and a YubiKey in a typical two-factor authentication (2FA) flow.

The demo implements the core cryptographic challenge-response system used in FIDO2. In this system, a user logs into a website with a username and password (1FA) and authenticates using a YubiKey (MFA). This README explains the project's major components, how to run the demo, and key features such as MFA management and YubiKey interactions.

---

## How to Run the Demo

### Prerequisites
Here are the necessary Python packages. If you do not have them, the `package_manager.py` script will handle automatic installation for you.

### Required Packages
- `argon2-cffi`
- `cryptography`
- `colorama`

These packages are automatically installed by running the demo if they aren't already available.

### Steps to Run
1. **Clone the repository:**

   ```bash
   git clone https://github.com/MFA-Phishing-MQP-WPI/Hardware-FIDO2-Implementation-Demo.git
   cd Hardware-FIDO2-Implementation-Demo
   ```
2. **Run the demo:**

   ```bash
   python3 demo.py
   ```
   
3. **Command Line Options:**
###### You can customize the execution of the demo using the following arguments:

* ##### `--launch-from-save [file_name].dump`: Restore the demo's state from a saved `.dump` file.
* ##### `-display_crypto_backend`: Display cryptographic backend actions.
* ##### `-debug_mode`: Print the values of private keys at runtime start.
* ##### `-help`: Display help and usage information.

###### Sample Usage:

   ```bash
   python3 demo.py --launch-from-save state.dump
   ```

## FIDO2 MFA Usage Demo
##### The FIDO2 MFA Usage Demo is a comprehensive demonstration of how YubiKey and FIDO2 prevent phishing attacks by verifying the RelyingParty (RP) ID during the authentication process. This demo allows you to explore how authentication works when using a legitimate service (`login.microsoftonline.com`) and how phishing attempts from an attacker (`attacker.vm`) are thwarted.

### Steps to Run
1. Basic Run Command
To start the demo using the saved system state `presentation.dump`, run the following command:
```bash
python3 demo.py --launch-from-save saved_states/presentation.dump
```
This will load the saved state where two Relying Parties (`login.microsoftonline.com` and `attacker.vm`) are set up, along with predefined user accounts such as `jacob_glik` and `craig`.

2. Running with All Flags (`-all` flag)
For a more detailed exploration, use the `-all` flag to enable additional debug and display features. This runs the demo with all available flags:
```bash
python3 demo.py -all --launch-from-save saved_states/presentation.dump
```
The -all flag activates the following options:
&nbsp;&nbsp; * `-display_crypto_backend`: Displays detailed information about actions completed by the cryptographic backend, helping users understand how the encryption and signing processes work.
&nbsp;&nbsp; * `-debug_mode`: Prints the value of all private keys at the runtime start, which is useful for those interested in the cryptographic details.
&nbsp;&nbsp; * `-debug_challenge`: Allows you to edit the challenge values before they are sent to the YubiKey for authentication. This is especially useful for testing different scenarios, such as attempting to spoof the challenge from an incorrect Relying Party.
&nbsp;&nbsp;* `-debug_yubikey`: Enables editing of the YubiKey’s internal values, giving the user more control over the authentication process.

These flags allow users to examine the authentication flow in depth and modify key components at runtime to simulate phishing attacks and RP mismatches.

### Demo Result
##### In the demo, you will observe how the system handles different login attempts:

&nbsp;&nbsp;⚠️ **Successful Login with a Password**: For accounts like `jacob_glik`, which only require a password, you will be able to log in on both `login.microsoftonline.com` and the phishing site `attacker.vm`.

&nbsp;&nbsp;✅ **Failure of Phishing Attempts with MFA**: For MFA-protected accounts like `craig`, you will see that login works on `login.microsoftonline.com` but fails on `attacker.vm`. The `client` will prevent the `YubiKey` from signing the `challenge` from the phishing site, highlighting the phishing-resistant nature of FIDO2. Even if the `attacker.vm` changes the value of the `Relying Party` in the `challenge` before passing it to the victim's `client`, the `YubiKey` will then generate the wrong `private key` and incorrectly sign the `challenge` leading to a decryption failure on the "real" `Relying Party` side. Blocking access to the attacker yet again.

### Exploring with `-debug_challenge` and `-debug_yubikey` Flags
1. `-debug_challenge`:
&nbsp;&nbsp; * This flag lets you intercept and edit the `challenge` creation process before it is sent to the `YubiKey` for authentication.
&nbsp;&nbsp; * You can modify the values of the `challenge`, such as the `RP ID`, to see how the `YubiKey` generates a `private key` and how the `Relying Party` responds when the `signature` does not match the legitimate site.
&nbsp;&nbsp; * This feature is especially useful if you want to simulate what happens when a `challenge` is sent from a different `relying party` or user during runtime, giving you control over the authentication flow.
2. `-debug_yubikey`:
&nbsp;&nbsp; * With this flag, you can edit the values used inside the `YubiKey` itself. This allows you to see how altering the `YubiKey`’s internal state would affect the authentication process.
&nbsp;&nbsp; * By modifying the `YubiKey`’s behavior or values during runtime, you can explore different security scenarios and understand how the `YubiKey` protects against tampered or incorrect inputs.

The [FIDO2 MFA Usage Demo](#-FIDO2-MFA-Usage-Demo) showcases the power of `YubiKey` (or other **hardware** security tokens) and `FIDO2` to protect against phishing attacks by preventing attestation `challenges` from unauthorized `Relying Parties`. By running the demo with the `-all` flag and exploring the `-debug_challenge` and `-debug_yubikey` flags, you can see how the system detects and stops phishing attempts, even when credentials are stolen. This detailed exploration of `YubiKey`'s anti-phishing mechanisms highlights why FIDO2 is a robust and secure MFA method.

## Important Classes and Their Functions

1. UserInterface

###### Manages interactions between the user and the system, simulating user input and the hardware insertion process for YubiKeys.

* ##### `new_YubiKey()`: Creates a new YubiKey with a unique ID and secret key.
* ##### `login()`: Simulates a user logging into a website with username + password, and performing 2FA with a YubiKey.
* ##### `insert_yubikey()`: Handles the user inserting their YubiKey.
* ##### `YubiKey_auth()`: Simulates the challenge-response process with the YubiKey.

2. Client

###### Simulates a browser (e.g., Chrome) interacting with websites and performing actions such as logging in.

* ##### `connect()`: Establishes a connection between the client and a website.
* ##### `_login_user()`: Manages the login process with username, password, and YubiKey authentication.

3. RelyingParty

###### Represents a web service that manages user accounts and the 2FA challenge process.

* ##### `add_account()`: Adds a new user account with a hashed password.
* ##### `grant_session_token_1FA()`: Grants a session token upon successful login with 1FA.
* ##### `grant_session_token_MFA()`: Validates the YubiKey challenge response and grants an MFA session token.
* ##### `request_challenge()`: Generates a cryptographic challenge for the YubiKey during 2FA.

4. YubiKey

###### Simulates a YubiKey security token, generating key pairs and signing challenges.

* ##### `_generate_key_pair()`: Generates a deterministic EC private-public key pair using HMAC-SHA256.
* ##### `auth_2FA()`: Handles the challenge-response process by signing a nonce with the private key.
* ##### `_sign()`: Signs a cryptographic challenge using the YubiKey's private key.

5. SessionToken

###### Represents a session token issued by the relying party, granting access to a user.

* ##### `is_valid()`: Checks if the token is still valid.
* ##### `add_nonce()`: Adds a nonce (a unique, random number) for cryptographic challenges.

6. OperatingSystem

###### Simulates the user's operating system, managing YubiKeys and client processes.

* ##### `new_YubiKey()`: Creates a new YubiKey and registers it with the system.
* ##### `boot_client()`: Starts a new client (browser) to interact with the system.
* ##### `connect_to_internet()`: Establishes a connection between the client and the relying party.
* ##### `approve_mfa_registration_request()`: Approves MFA registration requests made by the relying party via the client.


## How the Demo Works

1. Client Connection:
   1. The client connects to a relying party (e.g., login.microsoft.com).

2. Account Registration:
   1. The user creates a new account by providing a username and password.

3. MFA Registration:
   1. The user adds MFA to their account by registering a YubiKey.

4. Login Process:
   1. The user logs in with their username and password (1FA). If MFA is required, the system requests the insertion of the user's YubiKey.

5. Challenge Generation:
   1. The relying party generates a cryptographic challenge, which is sent to the YubiKey for signing.

6. Challenge Signing:
   1. The YubiKey signs the challenge using its private key, and the signed response is sent back to the relying party.

7. MFA Validation:
   1. The relying party verifies the signature. If it’s correct, the user is granted a session token and successfully logged in.


## Visualizing Logs

###### The demo includes detailed color-coded print statements that explain each step of the process:

* ##### `Green`: `RelyingParty` display only.
   * `RelyingParty`: actions such as secure storage and authentication.
* ##### `Red`: `Errors` and `OperatingSystem` display.
   * `Errors`: general errors.
   * `OperatingSystem`: Interfacing with user.
* ##### `Blue`: `Client` display only.
   * `Client`: actions such as connection requests.
* ##### `Yellow`: `Warnings` and `YubiKey` display.
   * `Warnings` general warnings.
   * `YubiKey` operations, including cryptographic signing and challenge responses.

###### The backend logging system provides verbose output of the cryptographic operations, user actions, and system decisions.


## Future Work
###### The following features will be added in future iterations:

* Additional secure account actions, such as sending emails or viewing secure data.

## Troubleshooting
###### If the automatic package installation fails, you can manually install the required packages with:

   ```bash
   pip install argon2-cffi cryptography colorama
   ```

## Already Implemented

### Main Menu Actions
#### ✔️ Add Browser
#### ✔️ Add YubiKey
#### ✔️ Connect to Website
#### ✔️ Save State
#### ✔️ Load From Previous State
### Website Actions
#### ✔️ Create New Account
#### ✔️ Login (1FA)
#### ✔️ Login (MFA)
#### ✔️ Add MFA
#### ✔️ Change Password
#### ✔️ View Account Info
#### ❌ Additional Secure Actions


## Resources

* [FIDO2 Specifications and Background](https://fidoalliance.org/specifications/)
* [FIDO2 Authentication Specifications](https://fidoalliance.org/fido2/)
* [WebAuthn Confluence Main](https://www.w3.org/TR/webauthn/)






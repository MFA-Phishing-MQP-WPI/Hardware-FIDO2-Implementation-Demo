# FIDO2 Authentication Demo Using YubiKey

## Table of Contents
1. [Overview](#overview)
2. [How to Run the Demo](#how-to-run-the-demo)
   - [Prerequisites](#prerequisites)
   - [Required Packages](#required-packages)
   - [Steps to Run](#steps-to-run)
3. [Important Classes and Their Functions](#important-classes-and-their-functions)
   - [UserInterface](#1-userinterface)
   - [Client](#2-client)
   - [RelyingParty](#3-relyingparty)
   - [YubiKey](#4-yubikey)
   - [SessionToken](#5-sessiontoken)
   - [OperatingSystem](#6-operatingsystem)
4. [How the Demo Works](#how-the-demo-works)
5. [Visualizing Logs](#visualizing-logs)
6. [Future Work](#future-work)
7. [Troubleshooting](#troubleshooting)
8. [Already Implemented](#already-implemented)

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
   cd fido2-demo
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
### Website Actions
#### ✔️ Create New Account
#### ✔️ Login (1FA)
#### ✔️ Login (MFA)
#### ✔️ Add MFA
#### ✔️ Change Password
#### ✔️ View Account Info
#### ❌ Additional Secure Actions





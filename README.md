# FIDO2 Authentication Demo Using YubiKey

<br>

## Overview

This repository contains a Python-based demo that simulates how FIDO2 authentication works using a YubiKey-like hardware security token. The `util.py` file includes the core implementation, which demonstrates the interactions between a client (browser), a relying party (web service), and a YubiKey (hardware security token) in a typical FIDO2 two-factor authentication (2FA) flow.

The demo showcases the fundamental mechanisms of a cryptographic challenge-response system, where a user logs into a website using a username, password (1FA), and YubiKey (MFA). This README explains the major components of the `util.py` file and the flow of authentication.

<br>

<br>

## How to Run the Demo

To run the demo:
1. Clone this repository and ensure you have Python 3 installed.
2. Run the demo: 
   ```bash
   python3 demo.py
   ```
3. Looking for more options? 
   ```bash
   python3 demo.py -help
   ```

<br>

<br>

## Important Classes and Their Functions

### 1. **UserInterface**
The `UserInterface` class manages interactions between the user and the system, simulating user input and the hardware insertion process for YubiKeys. Key features include:
- **`new_YubiKey()`**: Creates a new YubiKey with a unique ID and secret key.
- **`login()`**: Simulates a user logging into a website by entering their username, password, and performing 2FA with a YubiKey.
- **`insert_yubikey()`**: Handles the process of the user inserting their YubiKey into the system.
- **`YubiKey_auth()`**: Simulates a challenge being sent to a YubiKey for authentication.

### 2. **Client**
The `Client` class simulates a browser or user agent, such as `Chrome.exe`, interacting with websites and performing various actions (e.g., logging in). Key features include:
- **`connect()`**: Establishes a connection between the client and a website (relying party).
- **`_login_user()`**: Manages the process of logging in a user, handling both 1FA (username and password) and 2FA (YubiKey authentication).

### 3. **RelyingParty**
The `RelyingParty` class represents a web service (e.g., `login.microsoft.com`) that manages user accounts and the 2FA challenge process. It tracks accounts, session tokens, and YubiKey-related data. Key features include:
- **`add_account()`**: Adds a new user account with a hashed password.
- **`grant_session_token_1FA()`**: Grants a session token upon successful login with 1FA (username and password).
- **`grant_session_token_MFA()`**: Validates the YubiKey challenge response and issues an MFA session token.
- **`request_challenge()`**: Generates a cryptographic challenge for the YubiKey during the 2FA process.

### 4. **YubiKey**
The `YubiKey` class simulates a physical YubiKey security device. It generates cryptographic key pairs, signs challenges, and authenticates users. Key features include:
- **`_generate_key_pair()`**: Generates an EC (elliptic curve) private-public key pair using HMAC-SHA256 for deterministic key generation.
- **`auth_2FA()`**: Handles the challenge-response process by signing a nonce (random number) from the Relying Party using the private key.
- **`_sign()`**: Signs a cryptographic challenge using the private key stored on the YubiKey.

### 5. **SessionToken**
The `SessionToken` class represents a session token issued by the RelyingParty, which is used to grant access to a user. It tracks token expiration and validates the session for both 1FA and MFA. Key features include:
- **`is_valid()`**: Checks if the token is still valid and hasn't expired.
- **`add_nonce()`**: Adds a nonce (a unique, random number) to the token for cryptographic challenge purposes.

### 6. **YubiKeyResponse**
The `YubiKeyResponse` class encapsulates the response from the YubiKey after it processes a cryptographic challenge. It contains:
- `signature`: The cryptographic signature generated by the YubiKey.
- `nonce`: The original nonce (random number) sent by the Relying Party.
- `YubiKeyID`: The unique ID of the YubiKey.

<br>

<br>

## How the Demo Works

The demo shows the flow of a user logging into a website with 1FA (username and password) and then performing 2FA using a YubiKey. Here's a simplified step-by-step process:

1. **Client Connection**: The `Client` connects to a `RelyingParty` (e.g., `login.microsoft.com`)

2. **Account Registration**: The `User` requests to add a `username + password` combo to the `RelyingParty`, which is passed through the `Client`.
   1. Steps are followed to ensure security during the signup process.

3. **MFA Registration**: The `User` requests to add a form of MFA to their account.
   
4. **1FA Login**: The user inputs their username and password. If correct, a short-lived session token (1FA) is granted.

5. **2FA Request**: If the user's account requires 2FA, the system requests the insertion of the user's YubiKey.

6. **YubiKey Challenge**: The Relying Party generates a cryptographic challenge (a nonce) and sends it to the YubiKey for signing.

7. **Challenge Signing**: The YubiKey signs the challenge with its private key, generating a `YubiKeyResponse` with the signed nonce.

8. **MFA Validation**: The Relying Party verifies the signature and, if correct, grants the user a long-term session token (MFA).

<br>

<br>

## Future Work
###### In future iterations of this demo, the following features will be added:
* **Color-coded print statements:** Each step and function will have color-coded print statements explaining what they are doing. For example, YubiKey operations will be printed in blue, displaying cryptographic operations, while the Relying Party (RP) will be printed in red, showing account verification and token management processes.


<br>

<be>

## Already Implemented

### Main Menu Actions
##### ✔️ `Add Browser`
##### ✔️ `Add YubiKey`
##### ✔️ `Connect to website`

### Website Logged-Out Actions
##### ✔️ `Close Connection` / `Go back to the main menu`
##### ✔️ `Add a new account`
##### ✔️ `Login (1FA)`
##### ✔️ `Login (MFA)`

### Website Logged-In Actions
##### ✔️ `Close Connection` / `Go back to the main menu`
##### ✔️ `Add MFA`
##### ✔️ `Change Password`
##### ✔️ `Update MFA`
##### ❌ Brainstorm other `secure account actions` like `Send an email`, `view inbox`, and other secure actions

### Backend Actions
##### ✔️ `Create New Browser`
##### ✔️ `Create new YubiKey`
##### ✔️ `Create new RelyingParty`
##### ✔️ `Administer new SessionToken`
##### ✔️ `Varify SessionToken Validity`
* ###### ✔️ `SessionToken For Correct Account`
* ###### ✔️ `SessionToken Not Expired or Timmed Out`
* ###### ✔️ `SessionToken Still Active` `(Not Revoked)`
* ###### ✔️ `SessionToken For Correct Website`
##### ✔️ `Create new UserFacingConnection`
##### ✔️ `Complete UserFacingConnection Actions`
##### ✔️ `Interface with all classes from demo class` classes: [`Browser`, `YubiKey`, `RelyingParty`, `UserInterface`, `Connection`, `UserFacingConnection`, `AccountActions`]






<br>

<br>

<br>

<br>

<br>

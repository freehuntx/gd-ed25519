# Ed25519 GDExtension for Godot 4

A GDExtension for Godot 4 that brings high-performance, secure **Ed25519** public-key signatures and **X25519** authenticated public-key encryption to the Godot engine. 

Under the hood, this extension employs the highly-regarded, lightweight [Monocypher](https://monocypher.org/) cryptographic library for fast and secure operations.

## Features

- **Key Generation**: Easily generate secure Ed25519/X25519 keypairs.
- **Ed25519 Signatures**: Cryptographically sign messages and verify signatures to ensure data authenticity and integrity.
- **X25519 Authenticated Encryption**: Securely encrypt and decrypt data intended for a specific recipient using public-key cryptography.
- **Lightweight & Fast**: Uses the minimal and fast Monocypher library in C.

## Installation

### Using Precompiled Binaries

1. Download the latest release from the Releases page (if available).
2. Extract the archive and copy the `addons/ed25519` folder into your Godot project's `addons/` directory.
3. Open your Godot project. The engine will automatically load the extension. (Make sure to enable any editor plugins if added in the future).

### Building From Source

Prerequisites:
- [Godot 4](https://godotengine.org/) engine executable
- [SCons](https://scons.org/) build system
- A C++ compiler (GCC, Clang, or MSVC)

1. Clone this repository and update the `godot-cpp` submodule:
   ```bash
   git clone --recursive <repository_url> gd-ed25519
   cd gd-ed25519
   ```
   *(If you've already cloned it without submodules, run `git submodule update --init --recursive`)*

2. Build the GDExtension for your platform using SCons:
   ```bash
   # For Linux
   scons platform=linux target=template_debug
   
   # For Windows
   scons platform=windows target=template_debug
   
   # For macOS
   scons platform=macos target=template_debug
   ```

3. The compiled extension libraries will be placed in `project/addons/ed25519/`.
4. Copy the `addons/ed25519` directory into your Godot project.

## Usage Guide (GDScript)

Once installed, the `Ed25519` and `Ed25519Keypair` classes are registered globally in GDScript.

### 1. Generating a Keypair

```gdscript
var crypto = Ed25519.new()
var keypair: Ed25519Keypair = crypto.generate_keypair()

var private_key = keypair.get_private_key()
var public_key = keypair.get_public_key()

print("Public Key: ", public_key.hex_encode())
```

### 2. Signing and Verifying (Ed25519)

```gdscript
var crypto = Ed25519.new()
var keypair = crypto.generate_keypair()

var message = "Hello Godot!".to_utf8_buffer()

# Sign the message
var signature = crypto.sign(message, keypair.get_private_key(), keypair.get_public_key())
print("Signature: ", signature.hex_encode())

# Verify the signature
var is_valid = crypto.verify(signature, message, keypair.get_public_key())
if is_valid:
    print("Signature is valid! The message is authentic.")
else:
    print("Invalid signature!")
```

### 3. Public-Key Encryption and Decryption (X25519)

You can exchange encrypted messages securely using each party's keypair.

```gdscript
var crypto = Ed25519.new()

# Alice and Bob generate their own keypairs
var alice_keys = crypto.generate_keypair()
var bob_keys = crypto.generate_keypair()

var secret_message = "Top secret data!".to_utf8_buffer()

# Alice encrypts a message for Bob using Bob's public key and Alice's private key
var encrypted_data = crypto.encrypt(secret_message, bob_keys.get_public_key(), alice_keys.get_private_key())

# Bob decrypts the message using Alice's public key and Bob's private key
var decrypted_data = crypto.decrypt(encrypted_data, alice_keys.get_public_key(), bob_keys.get_private_key())

var original_text = decrypted_data.get_string_from_utf8()
print("Decrypted: ", original_text)
```

## License

This project relies on the underlying licensing of:
- **Godot Engine and godot-cpp**: MIT License
- **Monocypher**: Public Domain (CC-0) / 2-clause BSD

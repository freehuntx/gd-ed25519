extends Node

func _ready():
	print("Testing Ed25519...")
	
	var crypto = Ed25519.new()
	
	# 1. Test Key Generation
	var alice_keys = crypto.generate_keypair()
	var bob_keys = crypto.generate_keypair()
	
	print("Alice Public Key: ", alice_keys.public_key.hex_encode())
	print("Bob Public Key: ", bob_keys.public_key.hex_encode())
	
	# 2. Test Ed25519 Signing and Verification
	var message = "Hello, Godot!".to_utf8_buffer()
	var signature = crypto.sign(message, alice_keys.private_key, alice_keys.public_key)
	
	print("Signature: ", signature.hex_encode())
	
	var is_valid = crypto.verify(signature, message, alice_keys.public_key)
	print("Signature Valid: ", is_valid)
	
	var is_invalid = crypto.verify(signature, "Wrong message".to_utf8_buffer(), alice_keys.public_key)
	print("Invalid Signature Rejected: ", not is_invalid)
	
	# 3. Test X25519 Encryption and Decryption
	var secret_message = "Top secret data".to_utf8_buffer()
	
	# Alice encrypts a message for Bob
	var encrypted = crypto.encrypt(secret_message, bob_keys.public_key, alice_keys.private_key)
	print("Encrypted Data: ", encrypted.hex_encode())
	
	# Bob decrypts the message from Alice
	var decrypted = crypto.decrypt(encrypted, alice_keys.public_key, bob_keys.private_key)
	print("Decrypted Message: ", decrypted.get_string_from_utf8())
	
	if decrypted == secret_message:
		print("Encryption/Decryption SUCCESS!")
	else:
		print("Encryption/Decryption FAILED!")
		
	get_tree().quit()

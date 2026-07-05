extends SceneTree

# Headless test suite for the gd-ed25519 crypto-backend extension.
# Run with: godot --headless -s res://tests/test.gd
# Covers the following test vectors and features:
#   - RFC 8032 §7.1 (Ed25519, SHA-512) TEST 1 and TEST 3
#   - RFC 7748 §5.2 scalar-mult + §6.1 Diffie-Hellman (X25519)
#   - draft-irtf-cfrg-xchacha A.3 (XChaCha20-Poly1305 AEAD)
#   - RFC 7693 Appendix A (BLAKE2b, "abc", 64-byte digest)
#   - Seed round-trip identity + size rejection
#   - AEAD round-trip (empty/small/large, ±ad) + single-bit-flip smoke test
#   - Backward compatibility of the legacy encrypt/decrypt API

var failures: int = 0
var passes: int = 0

func _init():
	pass

func _initialize():
	print("=== gd-ed25519 crypto-backend tests ===")
	_test_ed25519_rfc8032()
	_test_keypair_seed_api()
	_test_x25519_rfc7748()
	_test_aead_xchacha()
	_test_blake2b_rfc7693()
	_test_legacy_encrypt_decrypt()
	print("\n=== Results: %d passed, %d failed ===" % [passes, failures])
	if failures != 0:
		quit(1)
	else:
		quit()

func check(condition: bool, name: String) -> void:
	if condition:
		passes += 1
		print("  PASS  %s" % name)
	else:
		failures += 1
		print("  FAIL  %s" % name)

func h(s: String) -> PackedByteArray:
	return s.hex_decode()

# ---------------------------------------------------------------------------
# RFC 8032 Ed25519 (SHA-512) signatures
# ---------------------------------------------------------------------------
func _test_ed25519_rfc8032() -> void:
	print("\n[RFC 8032] Ed25519 (SHA-512) signatures")

	# RFC 8032 §7.1 TEST 1 (empty message)
	var t1_secret := h("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	var t1_public := h("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
	var t1_sig := h("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
	var t1_msg := PackedByteArray()

	var sig1 := Ed25519.sign(t1_msg, t1_secret, t1_public)
	check(sig1 == t1_sig, "RFC8032 TEST1 sign produces expected signature")
	check(Ed25519.verify(t1_sig, t1_msg, t1_public), "RFC8032 TEST1 verify accepts signature")

	# from_seed should reconstruct the same public key
	var kp1 := Ed25519Keypair.from_seed(t1_secret)
	check(kp1 != null, "RFC8032 TEST1 from_seed returns non-null")
	check(kp1.get_public_key() == t1_public, "RFC8032 TEST1 from_seed public key matches")

	# RFC 8032 §7.1 TEST 3
	var t3_secret := h("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7")
	var t3_public := h("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025")
	var t3_msg := h("af82")
	var t3_sig := h("6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a")

	var sig3 := Ed25519.sign(t3_msg, t3_secret, t3_public)
	check(sig3 == t3_sig, "RFC8032 TEST3 sign produces expected signature")
	check(Ed25519.verify(t3_sig, t3_msg, t3_public), "RFC8032 TEST3 verify accepts signature")

	# Negative: tampered message must fail verification
	check(not Ed25519.verify(t3_sig, h("af83"), t3_public), "RFC8032 TEST3 verify rejects tampered message")
	# Negative: tampered signature must fail verification
	var bad_sig := t3_sig.duplicate()
	bad_sig[0] ^= 0x01
	check(not Ed25519.verify(bad_sig, t3_msg, t3_public), "RFC8032 TEST3 verify rejects tampered signature")

	# Size validation
	check(Ed25519.sign(t3_msg, PackedByteArray(), t3_public).size() == 0, "Ed25519.sign rejects bad private key size")
	check(not Ed25519.verify(t3_sig, t3_msg, PackedByteArray()), "Ed25519.verify rejects bad public key size")

	# Interop check: signature produced by from_seed keypair matches direct sign
	var kp3 := Ed25519Keypair.from_seed(t3_secret)
	var sig3_via_kp := Ed25519.sign(t3_msg, kp3.get_seed(), kp3.get_public_key())
	check(sig3_via_kp == t3_sig, "from_seed keypair signs identically to the raw seed")

	# Security property: Ed25519.sign binds the public key to the seed.
	#  - empty public_key  -> derive (canonical), yields the RFC signature.
	#  - matching public_key -> same signature.
	#  - mismatched public_key -> fail-fast (empty signature + error), so a
	#    caller bug / key-extraction attempt is surfaced rather than masked.
	var sig_nopk := Ed25519.sign(t3_msg, t3_secret, PackedByteArray())
	check(sig_nopk == t3_sig, "sign with empty public_key derives pk and matches RFC vector")
	var sig_matchpk := Ed25519.sign(t3_msg, t3_secret, t3_public)
	check(sig_matchpk == t3_sig, "sign with matching public_key matches RFC vector")
	var wrong_pk := PackedByteArray()
	wrong_pk.resize(32)
	for i in range(32):
		wrong_pk[i] = t3_public[i] ^ 0xFF
	var sig_wrongpk := Ed25519.sign(t3_msg, t3_secret, wrong_pk)
	check(sig_wrongpk.size() == 0, "sign with mismatched public_key fails fast (empty signature)")

# ---------------------------------------------------------------------------
# Keypair seed API
# ---------------------------------------------------------------------------
func _test_keypair_seed_api() -> void:
	print("\n[SEED API] Keypair from seed")

	var k := Ed25519Keypair.generate()
	check(k != null, "generate() returns non-null")
	check(k.get_seed().size() == 32, "generated seed is 32 bytes")
	check(k.get_public_key().size() == 32, "generated public key is 32 bytes")

	# from_seed(k.get_seed()) yields a byte-identical keypair
	var k2 := Ed25519Keypair.from_seed(k.get_seed())
	check(k2 != null, "from_seed round-trip returns non-null")
	check(k2.get_public_key() == k.get_public_key(), "from_seed public key byte-identical to original")

	var msg := "round-trip identity".to_utf8_buffer()
	var s1 := Ed25519.sign(msg, k.get_seed(), k.get_public_key())
	var s2 := Ed25519.sign(msg, k2.get_seed(), k2.get_public_key())
	check(s1 == s2, "from_seed keypair signs byte-identically to original")

	# Seed length rejection: 31 and 33 bytes must fail
	var bad31 := PackedByteArray()
	bad31.resize(31)
	var r31 := Ed25519Keypair.from_seed(bad31)
	check(r31 == null, "from_seed rejects 31-byte seed")
	var bad33 := PackedByteArray()
	bad33.resize(33)
	var r33 := Ed25519Keypair.from_seed(bad33)
	check(r33 == null, "from_seed rejects 33-byte seed")

	# 64-byte libsodium-format import: first 32 bytes are the seed
	var libsodium_fmt := k.get_seed() + k.get_public_key()
	var k3 := Ed25519Keypair.from_seed(libsodium_fmt)
	check(k3 != null, "from_seed accepts 64-byte libsodium-format input")
	if k3 != null:
		check(k3.get_public_key() == k.get_public_key(), "64-byte import yields matching public key")
		check(k3.get_seed() == k.get_seed(), "64-byte import seed matches first 32 bytes")

	# Deprecated aliases still work
	var k4 := Ed25519Keypair.from_private_key(k.get_seed())
	check(k4 != null, "deprecated from_private_key still returns a keypair")
	if k4 != null:
		check(k4.get_public_key() == k.get_public_key(), "deprecated from_private_key yields matching public key")
		check(k4.get_private_key() == k.get_seed(), "deprecated get_private_key returns the seed")

# ---------------------------------------------------------------------------
# X25519 (RFC 7748) key agreement
# ---------------------------------------------------------------------------
func _test_x25519_rfc7748() -> void:
	print("\n[X25519] RFC 7748 key agreement")

	# RFC 7748 §5.2 scalar-multiplication test vectors.
	# crypto_x25519(scalar, basepoint) where basepoint is the input u-coordinate.
	var scalar0 := h("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
	var u0 := h("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
	var out0 := h("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
	var r0: Variant = X25519.shared_secret(scalar0, u0)
	check(r0 != null, "RFC7748 §5.2 row 0 returns non-null")
	if r0 != null:
		check(r0 == out0, "RFC7748 §5.2 row 0 output matches")

	var scalar1 := h("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d")
	var u1 := h("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493")
	var out1 := h("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957")
	var r1: Variant = X25519.shared_secret(scalar1, u1)
	check(r1 != null, "RFC7748 §5.2 row 1 returns non-null")
	if r1 != null:
		check(r1 == out1, "RFC7748 §5.2 row 1 output matches")

	# RFC 7748 §6.1 Diffie-Hellman example
	var alice_sk := h("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
	var alice_pk := h("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
	var bob_sk := h("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
	var bob_pk := h("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
	var shared := h("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")

	# Direct scalar-mult check: Alice's public key from her private key.
	# We use the RFC private keys directly with shared_secret (which is raw
	# crypto_x25519). The "public key" in X25519 terms is x25519_public_key(sk);
	# shared_secret(sk, pk) gives the DH result.
	var s_ab: Variant = X25519.shared_secret(alice_sk, bob_pk)
	var s_ba: Variant = X25519.shared_secret(bob_sk, alice_pk)
	check(s_ab != null, "RFC7748 §6.1 Alice->Bob DH returns non-null")
	check(s_ba != null, "RFC7748 §6.1 Bob->Alice DH returns non-null")
	if s_ab != null and s_ba != null:
		check(s_ab == shared, "RFC7748 §6.1 Alice shared secret matches 4a5d9d5b...")
		check(s_ba == shared, "RFC7748 §6.1 Bob shared secret matches 4a5d9d5b...")
		check(s_ab == s_ba, "RFC7748 §6.1 both directions agree")

	# Generate ephemeral keypair and confirm private/public sizes.
	var e := X25519.generate_keypair()
	check(e != null, "X25519.generate_keypair returns non-null")
	if e != null:
		check(e.get_private_key().size() == 32, "ephemeral X25519 private key is 32 bytes")
		check(e.get_public_key().size() == 32, "ephemeral X25519 public key is 32 bytes")
		# A round-trip DH between two ephemeral keypairs must agree.
		var e2 := X25519.generate_keypair()
		var dh1: Variant = X25519.shared_secret(e.get_private_key(), e2.get_public_key())
		var dh2: Variant = X25519.shared_secret(e2.get_private_key(), e.get_public_key())
		check(dh1 != null and dh1 == dh2, "ephemeral X25519 DH agrees in both directions")

	# Size validation
	check(X25519.shared_secret(PackedByteArray(), bob_pk) == null, "X25519.shared_secret rejects bad private size")
	check(X25519.shared_secret(alice_sk, PackedByteArray()) == null, "X25519.shared_secret rejects bad public size")

# ---------------------------------------------------------------------------
# XChaCha20-Poly1305 AEAD
# ---------------------------------------------------------------------------
func _test_aead_xchacha() -> void:
	print("\n[AEAD] XChaCha20-Poly1305")

	# draft-irtf-cfrg-xchacha Appendix A.3 test vector
	var key := h("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
	var nonce := h("404142434445464748494a4b4c4d4e4f5051525354555657")
	var pt := h("4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e")
	var aad := h("50515253c0c1c2c3c4c5c6c7")
	var ct_and_tag := h("bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52ec0875924c1c7987947deafd8780acf49")

	var enc: Variant = Monocypher.aead_encrypt(key, nonce, pt, aad)
	check(enc != null, "A.3 aead_encrypt returns non-null")
	if enc != null:
		check(enc == ct_and_tag, "A.3 ciphertext||tag matches draft vector")

	var dec: Variant = Monocypher.aead_decrypt(key, nonce, ct_and_tag, aad)
	check(dec != null, "A.3 aead_decrypt returns non-null")
	if dec != null:
		check(dec == pt, "A.3 decrypted plaintext matches original")

	# `ad` is optional: omitting it must be equivalent to passing an empty
	# PackedByteArray (the binding declares DEFVAL(PackedByteArray())).
	var enc_noad: Variant = Monocypher.aead_encrypt(key, nonce, pt)
	check(enc_noad != null, "aead_encrypt without ad arg returns non-null")
	if enc_noad != null:
		var enc_emptyad: Variant = Monocypher.aead_encrypt(key, nonce, pt, PackedByteArray())
		check(enc_noad == enc_emptyad, "omitting ad equals passing empty ad")
		var dec_noad: Variant = Monocypher.aead_decrypt(key, nonce, enc_noad)
		check(dec_noad != null and dec_noad == pt, "aead_decrypt without ad arg round-trips")

	# Round-trip: empty / small / large (>=1 MiB) plaintexts, with and without ad.
	_rng_self_round_trip(key, nonce)
	_large_round_trip(key, nonce)

	# Single-bit-flip smoke test: flipping one bit in each of ciphertext body,
	# tag, ad, nonce, and key must make decrypt return null. This is a smoke
	# test (one representative bit per field), not an exhaustive matrix over
	# every bit position.
	_bit_flip_matrix(key, nonce, pt, aad)

	# Empty plaintext round-trip (must distinguish empty from failure).
	var empty_pt := PackedByteArray()
	var e_ad := h("deadbeef")
	var e_enc: Variant = Monocypher.aead_encrypt(key, nonce, empty_pt, e_ad)
	check(e_enc != null, "empty-plaintext aead_encrypt returns non-null")
	if e_enc != null:
		check(e_enc.size() == 16, "empty-plaintext ciphertext||tag is just the 16-byte tag")
		var e_dec: Variant = Monocypher.aead_decrypt(key, nonce, e_enc, e_ad)
		check(e_dec != null, "empty-plaintext aead_decrypt returns non-null (not failure)")
		if e_dec != null:
			check(typeof(e_dec) == TYPE_PACKED_BYTE_ARRAY, "empty-plaintext decrypt is a PackedByteArray")
			check((e_dec as PackedByteArray).size() == 0, "empty-plaintext decrypt is an empty array, not null")

	# Size validation
	check(Monocypher.aead_encrypt(PackedByteArray(), nonce, pt, aad) == null, "aead_encrypt rejects 0-byte key")
	var bad_nonce := PackedByteArray(); bad_nonce.resize(12)
	check(Monocypher.aead_encrypt(key, bad_nonce, pt, aad) == null, "aead_encrypt rejects 12-byte (non-XChaCha) nonce")
	check(Monocypher.aead_decrypt(key, nonce, PackedByteArray(), aad) == null, "aead_decrypt rejects <16-byte input")

func _rng_self_round_trip(key: PackedByteArray, nonce: PackedByteArray) -> void:
	for with_ad in [false, true]:
		var ad := h("aabbccdd") if with_ad else PackedByteArray()
		for size in [1, 7, 64, 256, 1024]:
			var pt := PackedByteArray()
			pt.resize(size)
			for i in range(size):
				pt[i] = (i * 7 + 3) & 0xFF
			var ct: Variant = Monocypher.aead_encrypt(key, nonce, pt, ad)
			if ct == null:
				check(false, "round-trip encrypt size=%d ad=%s" % [size, str(with_ad)])
				continue
			var dt: Variant = Monocypher.aead_decrypt(key, nonce, ct, ad)
			if dt == null:
				check(false, "round-trip decrypt size=%d ad=%s" % [size, str(with_ad)])
				continue
			check((dt as PackedByteArray) == pt, "round-trip size=%d ad=%s" % [size, str(with_ad)])

func _large_round_trip(key: PackedByteArray, nonce: PackedByteArray) -> void:
	# >= 1 MiB plaintext
	var size := 1024 * 1024 + 17
	var pt := PackedByteArray()
	pt.resize(size)
	for i in range(size):
		pt[i] = (i * 31 + 17) & 0xFF
	var ad := h("ff00ff00")
	var ct: Variant = Monocypher.aead_encrypt(key, nonce, pt, ad)
	if ct == null:
		check(false, "1MiB+ encrypt returned null")
		return
	if (ct as PackedByteArray).size() != size + 16:
		check(false, "1MiB+ ciphertext||tag size is %d, expected %d" % [(ct as PackedByteArray).size(), size + 16])
		return
	var dt: Variant = Monocypher.aead_decrypt(key, nonce, ct, ad)
	if dt == null:
		check(false, "1MiB+ decrypt returned null")
		return
	check((dt as PackedByteArray) == pt, "1MiB+ round-trip with ad")

func _bit_flip_matrix(key: PackedByteArray, nonce: PackedByteArray, pt: PackedByteArray, aad: PackedByteArray) -> void:
	var ct: Variant = Monocypher.aead_encrypt(key, nonce, pt, aad)
	if ct == null:
		check(false, "bit-flip smoke test: encrypt precondition failed")
		return
	var ct_pba: PackedByteArray = ct as PackedByteArray
	var ok := true

	# Flip a bit in the ciphertext body.
	var bad_ct := ct_pba.duplicate()
	bad_ct[0] ^= 0x01
	if Monocypher.aead_decrypt(key, nonce, bad_ct, aad) != null:
		ok = false; check(false, "bit-flip in ciphertext body NOT rejected")

	# Flip a bit in the tag (last 16 bytes).
	var bad_tag := ct_pba.duplicate()
	bad_tag[bad_tag.size() - 1] ^= 0x01
	if Monocypher.aead_decrypt(key, nonce, bad_tag, aad) != null:
		ok = false; check(false, "bit-flip in tag NOT rejected")

	# Flip a bit in the ad.
	var bad_ad := aad.duplicate()
	bad_ad[0] ^= 0x01
	if Monocypher.aead_decrypt(key, nonce, ct_pba, bad_ad) != null:
		ok = false; check(false, "bit-flip in ad NOT rejected")

	# Flip a bit in the nonce.
	var bad_nonce := nonce.duplicate()
	bad_nonce[0] ^= 0x01
	if Monocypher.aead_decrypt(key, nonce, ct_pba, aad) == null:  # unchanged nonce - sanity
		ok = false; check(false, "unchanged nonce decrypt should succeed (sanity)")
	if Monocypher.aead_decrypt(key, bad_nonce, ct_pba, aad) != null:
		ok = false; check(false, "bit-flip in nonce NOT rejected")

	# Flip a bit in the key.
	var bad_key := key.duplicate()
	bad_key[0] ^= 0x01
	if Monocypher.aead_decrypt(bad_key, nonce, ct_pba, aad) != null:
		ok = false; check(false, "bit-flip in key NOT rejected")

	if ok:
		check(true, "bit-flip smoke test: all 5 tampered decryptions rejected")

# ---------------------------------------------------------------------------
# BLAKE2b (RFC 7693)
# ---------------------------------------------------------------------------
func _test_blake2b_rfc7693() -> void:
	print("\n[BLAKE2b] RFC 7693")

	# RFC 7693 Appendix A: BLAKE2b-512 of "abc".
	var abc := "abc".to_utf8_buffer()
	var expected := h("ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923")
	var digest: Variant = Monocypher.blake2b(abc, 64)
	check(digest != null, "blake2b(\"abc\", 64) returns non-null")
	if digest != null:
		check((digest as PackedByteArray) == expected, "RFC7693 AppA blake2b-512(\"abc\") matches")
		check((digest as PackedByteArray).size() == 64, "blake2b-512 digest is 64 bytes")

	# Default out_len = 32
	var d32: Variant = Monocypher.blake2b(abc)
	check(d32 != null, "blake2b(\"abc\") default out_len returns non-null")
	if d32 != null:
		check((d32 as PackedByteArray).size() == 32, "blake2b default out_len is 32 bytes")

	# Bounds enforcement
	check(Monocypher.blake2b(abc, 0) == null, "blake2b rejects out_len=0")
	check(Monocypher.blake2b(abc, 65) == null, "blake2b rejects out_len=65")
	var d1: Variant = Monocypher.blake2b(abc, 1)
	check(d1 != null and (d1 as PackedByteArray).size() == 1, "blake2b out_len=1 accepted")

# ---------------------------------------------------------------------------
# Backward compatibility - legacy Ed25519 encrypt/decrypt (X25519 APKE)
# ---------------------------------------------------------------------------
func _test_legacy_encrypt_decrypt() -> void:
	print("\n[BACKCOMP] Legacy Ed25519 encrypt/decrypt")

	var alice := Ed25519Keypair.generate()
	var bob := Ed25519Keypair.generate()
	if alice == null or bob == null:
		check(false, "legacy: keypair generation failed")
		return

	var secret_msg := "Top secret data, round-tripped via legacy APKE".to_utf8_buffer()
	# Alice encrypts for Bob using her private key + Bob's public key.
	var enc := Ed25519.encrypt(secret_msg, bob.get_public_key(), alice.get_seed())
	check(enc.size() >= 40, "legacy encrypt produces a >=40-byte blob")
	if enc.size() < 40:
		return
	# Bob decrypts using his private key + Alice's public key.
	var dec := Ed25519.decrypt(enc, alice.get_public_key(), bob.get_seed())
	check(dec == secret_msg, "legacy decrypt recovers the original message")

	# Tampered ciphertext must fail.
	var bad := enc.duplicate()
	bad[bad.size() - 1] ^= 0x01
	var dec_bad := Ed25519.decrypt(bad, alice.get_public_key(), bob.get_seed())
	check(dec_bad.size() == 0, "legacy decrypt of tampered ciphertext returns empty")

	# Wrong key must fail.
	var eve := Ed25519Keypair.generate()
	var dec_wrong := Ed25519.decrypt(enc, alice.get_public_key(), eve.get_seed())
	check(dec_wrong.size() == 0, "legacy decrypt with wrong key returns empty")

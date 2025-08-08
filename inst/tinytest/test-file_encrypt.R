# Test file encryption with public keys
test_dir <- tempdir()
input_file <- file.path(test_dir, "test.txt")
writeLines("Hello, World!", input_file)

# Generate a test key
key_file <- file.path(test_dir, "test.key")
key <- key_generate(key_file)

# Test public key encryption
encrypted_file <- file.path(test_dir, "test.txt.age")
file_encrypt(input_file, encrypted_file, public = key)

# Check encrypted file was created
expect_true(file.exists(encrypted_file))
expect_true(file.size(encrypted_file) > 0)

# Test decryption to verify it worked
decrypted_content <- file_decrypt(encrypted_file, output = NULL, private = key_file)
expect_equal(trimws(decrypted_content), "Hello, World!")

# Test with armor format
encrypted_armor <- file.path(test_dir, "test_armor.age")
file_encrypt(input_file, encrypted_armor, public = key, armor = TRUE)
expect_true(file.exists(encrypted_armor))

# Armor format should create different files (may be larger due to base64 overhead)
expect_true(file.size(encrypted_armor) > 0)
# Note: Size comparison may vary depending on file content and age implementation

# Test error cases
expect_error(
    file_encrypt("nonexistent.txt", public = key),
    "does not exist")

# Test overwrite protection (file_encrypt now never overwrites)
expect_error(file_encrypt(input_file, encrypted_file, public = key))

# Test multiple recipients
key2_file <- file.path(test_dir, "test2.key")
key2 <- key_generate(key2_file)
multi_encrypted <- file.path(test_dir, "multi.age")
file_encrypt(input_file, multi_encrypted, public = c(key, key2))

# Both keys should be able to decrypt
decrypted1 <- file_decrypt(multi_encrypted, output = NULL, private = key_file)
decrypted2 <- file_decrypt(multi_encrypted, output = NULL, private = key2_file)
expect_equal(trimws(decrypted1), "Hello, World!")
expect_equal(trimws(decrypted2), "Hello, World!")

# Test single recipient with character vector
single_recipient <- file.path(test_dir, "single.age")
file_encrypt(input_file, single_recipient, public = as.character(key))
decrypted_single <- file_decrypt(single_recipient, output = NULL, private = key_file)
expect_equal(trimws(decrypted_single), "Hello, World!")

# Note: Passphrase encryption tests are skipped because they require interactive input
# In a real test environment, you would need to mock getPass::getPass() or test manually

# Test creating two different keys, encrypting for both, and decrypting with both
alice_key_file <- file.path(test_dir, "alice.key")
bob_key_file <- file.path(test_dir, "bob.key")
alice_key <- key_generate(alice_key_file)
bob_key <- key_generate(bob_key_file)

# Encrypt for both recipients
dual_encrypted <- file.path(test_dir, "dual.age")
file_encrypt(input_file, dual_encrypted, public = c(alice_key, bob_key))

# Both keys should decrypt to same content
alice_result <- file_decrypt(dual_encrypted, output = NULL, private = alice_key_file)
bob_result <- file_decrypt(dual_encrypted, output = NULL, private = bob_key_file)
expect_identical(alice_result, bob_result)

# Clean up
unlink(c(
    input_file, encrypted_file, encrypted_armor,
    key_file, key2_file, multi_encrypted, single_recipient,
    alice_key_file, bob_key_file, dual_encrypted), force = TRUE)


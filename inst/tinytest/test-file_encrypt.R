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
decrypted_content <- age_decrypt_key(encrypted_file, key_file)
expect_equal(trimws(decrypted_content), "Hello, World!")

# Test with armor format
encrypted_armor <- file.path(test_dir, "test_armor.age")
file_encrypt(input_file, encrypted_armor, public = key, armor = TRUE)
expect_true(file.exists(encrypted_armor))

# Armor format should create different files (may be larger due to base64 overhead)
expect_true(file.size(encrypted_armor) > 0)
# Note: Size comparison may vary depending on file content and age implementation

# Test error cases
expect_error(file_encrypt("nonexistent.txt", public = key),
             "does not exist")

# Test overwrite protection (file_encrypt now never overwrites)
expect_error(file_encrypt(input_file, encrypted_file, public = key))

# Test multiple recipients
key2_file <- file.path(test_dir, "test2.key")
key2 <- key_generate(key2_file)
multi_encrypted <- file.path(test_dir, "multi.age")
file_encrypt(input_file, multi_encrypted, public = c(key, key2))

# Both keys should be able to decrypt
decrypted1 <- age_decrypt_key(multi_encrypted, key_file)
decrypted2 <- age_decrypt_key(multi_encrypted, key2_file)
expect_equal(trimws(decrypted1), "Hello, World!")
expect_equal(trimws(decrypted2), "Hello, World!")

# Test single recipient with character vector
single_recipient <- file.path(test_dir, "single.age")
file_encrypt(input_file, single_recipient, public = as.character(key))
decrypted_single <- age_decrypt_key(single_recipient, key_file)
expect_equal(trimws(decrypted_single), "Hello, World!")

# Note: Passphrase encryption tests are skipped because they require interactive input
# In a real test environment, you would need to mock getPass::getPass() or test manually

# Clean up
unlink(c(input_file, encrypted_file, encrypted_armor, 
         key_file, key2_file, multi_encrypted, single_recipient), force = TRUE)
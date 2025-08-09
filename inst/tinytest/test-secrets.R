test_dir <- tempdir()

# Test basic lockbox format (use_sops = FALSE)
private_key <- file.path(test_dir, "test.key")
lockbox_file <- file.path(test_dir, "test.yaml")
sops_lockbox <- file.path(test_dir, "sops_test.yaml")

# Generate test key
key <- key_generate(private_key)
public_key <- key_recipient(private_key)

# Clean up any existing files
unlink(c(lockbox_file, sops_lockbox))

# Test 1: Basic lockbox encryption and decryption
secrets_encrypt(
    lockbox_file,
    public = public_key,
    secrets = list("TEST_VAR" = "test_value", "API_KEY" = "secret123"),
    sops = FALSE
)

expect_true(file.exists(lockbox_file))

# Test decryption
decrypted <- secrets_decrypt(lockbox_file, private = private_key)
expect_equal(decrypted$TEST_VAR, "test_value")
expect_equal(decrypted$API_KEY, "secret123")
expect_true(length(decrypted) == 2)

# Test 2: Export to environment variables
# Clear any existing env vars first
old_test_var <- Sys.getenv("TEST_VAR", unset = NA)
old_api_key <- Sys.getenv("API_KEY", unset = NA)
if (!is.na(old_test_var)) Sys.unsetenv("TEST_VAR")
if (!is.na(old_api_key)) Sys.unsetenv("API_KEY")

exported_vars <- secrets_export(lockbox_file, private = private_key)
expect_equal(sort(exported_vars), c("API_KEY", "TEST_VAR"))
expect_equal(Sys.getenv("TEST_VAR"), "test_value")
expect_equal(Sys.getenv("API_KEY"), "secret123")

# Test 3: Update existing lockbox file
secrets_encrypt(
    lockbox_file,
    private = private_key,
    secrets = list("NEW_SECRET" = "new_value", "API_KEY" = "updated_secret")
)

updated <- secrets_decrypt(lockbox_file, private = private_key)
expect_equal(updated$TEST_VAR, "test_value") # Should still be there
expect_equal(updated$API_KEY, "updated_secret") # Should be updated
expect_equal(updated$NEW_SECRET, "new_value") # Should be added
expect_true(length(updated) == 3)

# Test 4: Test is_sops() detection
expect_false(is_sops(lockbox_file))

# Test 5: Test with multiple recipients
second_key <- file.path(test_dir, "second.key")
key2 <- key_generate(second_key)
public_key2 <- key_recipient(second_key)
multi_lockbox <- file.path(test_dir, "multi.yaml")

secrets_encrypt(
    multi_lockbox,
    public = c(public_key, public_key2),
    secrets = list("SHARED_SECRET" = "shared_value"),
    sops = FALSE
)

# Both keys should be able to decrypt
decrypted1 <- secrets_decrypt(multi_lockbox, private = private_key)
decrypted2 <- secrets_decrypt(multi_lockbox, private = second_key)
expect_equal(decrypted1$SHARED_SECRET, "shared_value")
expect_equal(decrypted2$SHARED_SECRET, "shared_value")

# Test lockbox_recipients field with multiple recipients
multi_content <- yaml::yaml.load_file(multi_lockbox)
expect_true("lockbox_recipients" %in% names(multi_content))
expect_equal(length(multi_content$lockbox_recipients), 2)
expect_true(public_key %in% multi_content$lockbox_recipients)
expect_true(public_key2 %in% multi_content$lockbox_recipients)

# Test 6: Error cases for lockbox format
# Missing public key for new file
expect_error(
    secrets_encrypt("new.yaml", secrets = list("TEST" = "value")),
    "public"
)

# Missing private key for updating existing file
expect_error(
    secrets_encrypt(lockbox_file, secrets = list("TEST" = "value")),
    "private"
)

# Invalid file extension
expect_error(
    secrets_encrypt("test.txt", public = public_key, secrets = list("TEST" = "value")),
    "yaml extension"
)

# Test 7: Test SOPS format (if available)
sops_available <- tryCatch(
    {
        system("sops --version", ignore.stdout = TRUE, ignore.stderr = TRUE)
        TRUE
    },
    error = function(e) FALSE)

if (!sops_available) exit_file("Missing SOPS")

# Test SOPS encryption
secrets_encrypt(
    sops_lockbox,
    public = public_key,
    secrets = list("SOPS_VAR" = "sops_value"),
    sops = TRUE
)

expect_true(file.exists(sops_lockbox))
expect_true(is_sops(sops_lockbox))

# Test SOPS decryption
sops_decrypted <- secrets_decrypt(sops_lockbox, private = private_key)
expect_equal(sops_decrypted$SOPS_VAR, "sops_value")

# Test SOPS export
Sys.unsetenv("SOPS_VAR")
sops_exported <- secrets_export(sops_lockbox, private = private_key)
expect_true("SOPS_VAR" %in% sops_exported)
expect_equal(Sys.getenv("SOPS_VAR"), "sops_value")

# Test SOPS update
secrets_encrypt(
    sops_lockbox,
    private = private_key,
    secrets = list("SOPS_VAR2" = "sops_value2")
)

updated_sops <- secrets_decrypt(sops_lockbox, private = private_key)
expect_equal(updated_sops$SOPS_VAR, "sops_value")
expect_equal(updated_sops$SOPS_VAR2, "sops_value2")


# Test 8: Auto-detection behavior
auto_lockbox <- file.path(test_dir, "auto.yaml")
secrets_encrypt(
    auto_lockbox,
    public = public_key,
    secrets = list("AUTO_VAR" = "auto_value")
    # No use_sops parameter - should auto-detect
)

expect_true(file.exists(auto_lockbox))
auto_decrypted <- secrets_decrypt(auto_lockbox, private = private_key)
expect_equal(auto_decrypted$AUTO_VAR, "auto_value")

# Test 9: Test with empty secrets list
empty_lockbox <- file.path(test_dir, "empty.yaml")
secrets_encrypt(
    empty_lockbox,
    public = public_key,
    secrets = list(),
    sops = FALSE
)

empty_decrypted <- secrets_decrypt(empty_lockbox, private = private_key)
expect_true(length(empty_decrypted) == 0)

# Test 10: Test with special characters in secrets
special_lockbox <- file.path(test_dir, "special.yaml")
special_secrets <- list(
    "SPECIAL_CHARS" = "!@#$%^&*()_+-={}[]|\\:;\"'<>?,./"
)

secrets_encrypt(
    special_lockbox,
    public = public_key,
    secrets = special_secrets,
    sops = FALSE
)

special_decrypted <- secrets_decrypt(special_lockbox, private = private_key)
expect_equal(special_decrypted$SPECIAL_CHARS, special_secrets$SPECIAL_CHARS)

# Restore environment variables
if (!is.na(old_test_var)) {
    do.call("Sys.setenv", setNames(list(old_test_var), "TEST_VAR"))
} else {
    Sys.unsetenv("TEST_VAR")
}
if (!is.na(old_api_key)) {
    do.call("Sys.setenv", setNames(list(old_api_key), "API_KEY"))
} else {
    Sys.unsetenv("API_KEY")
}

# Clean up test files
unlink(c(
    private_key, lockbox_file, sops_lockbox, second_key, multi_lockbox,
    auto_lockbox, empty_lockbox, special_lockbox
), force = TRUE)


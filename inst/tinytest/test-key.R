path <- tempfile(fileext = ".key")
key <- key_generate(path)

# file was created with expected content
expect_true(file.exists(path))
key_content <- readLines(path)
expect_true(any(grepl("# created:", key_content)))
expect_true(any(grepl("# public key:", key_content)))
expect_true(any(grepl("AGE-SECRET-KEY-", key_content)))

# R object has the expected structure
expect_inherits(key, "lockbox_key")
expect_true(is.character(key))
expect_true(nchar(key) > 0)

# Test key_recipient function
recipient <- key_recipient(path)
expect_inherits(key, "lockbox_key")
expect_true(grepl("^age\\d", recipient))


# Clean up
unlink(path)

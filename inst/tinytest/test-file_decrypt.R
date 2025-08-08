## commented out because we no longer accept passphrase as an argument
# # passphrase decryption
# tf <- tempfile(fileext = ".txt")
# file_decrypt(
#     input = "data/passphrase.txt.age",
#     output = tf,
#     passphrase = "hello world")
# expect_equal(readLines(tf), "blah blah")

# key pair decryption
tf <- tempfile(fileext = ".txt")
file_decrypt(
    input = "data/key.txt.age",
    output = tf,
    private = "data/identity.key")
expect_equal(readLines(tf), "blah blah")

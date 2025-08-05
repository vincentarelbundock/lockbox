#' Encrypt a file using age
#'
#' Encrypt any file using age encryption with public key(s) or a passphrase.
#' The encrypted file will have a `.age` extension by default.
#'
#' @param input Character string. Path to the file to encrypt.
#' @param output Character string. Path for the encrypted output file. Defaults to `input.age`.
#' @param public Character vector or NULL. Public key(s) for encryption (age recipient identifiers).
#'   Must be provided if `passphrase = FALSE`.
#' @param passphrase Logical. If TRUE, prompts for a passphrase instead of using public keys.
#' @param armor Logical. If TRUE, outputs ASCII-armored format instead of binary.
#'
#' @return Invisibly returns the output file path.
#'
#' @examples
#' \dontrun{
#' # Encrypt with public key
#' key <- key_generate()
#' file_encrypt("sensitive.csv", public = key$public)
#'
#' # Encrypt with passphrase
#' file_encrypt("sensitive.csv", passphrase = TRUE)
#'
#' # Custom output path and ASCII armor
#' file_encrypt("data.txt", "encrypted_data.age", key$public, armor = TRUE)
#' }
#'
#' @export
file_encrypt <- function(input,
                         output = paste0(input, ".age"),
                         public = NULL,
                         passphrase = FALSE,
                         armor = FALSE) {
    assert_tools()
    args <- c()
    if (passphrase) {
        args <- c("--passphrase")
    } else if (!is.null(public)) {
        for (r in public) {
            args <- c(args, "-r", shQuote(r))
        }
    } else {
        stop("Either public or passphrase = TRUE must be set")
    }
    if (armor) args <- c(args, "--armor")
    args <- c(args, "-o", shQuote(output), shQuote(input))
    res <- system2("age", args = args)
    if (res != 0) stop("age encryption failed")
    invisible(output)
}


#' Decrypt an age-encrypted file
#'
#' Decrypt a file that was encrypted with age. Can use a private key or key file.
#'
#' @param input Character string. Path to the encrypted `.age` file.
#' @param output Character string. Path for the decrypted output file. Defaults to removing `.age` extension.
#' @param private Character string or NULL. Private key for decryption. Can be:
#'   - A private key string starting with "AGE-SECRET-KEY-1"
#'   - Path to an age identity file
#'   - NULL to prompt for private key input
#'
#' @return Invisibly returns the output file path.
#'
#' @examples
#' \dontrun{
#' # Decrypt with private key string
#' key <- key_generate()
#' file_decrypt("sensitive.csv.age", private = key$private)
#'
#' # Decrypt with key file
#' file_decrypt("sensitive.csv.age", private = "identity.key")
#'
#' # Decrypt with prompted private key
#' file_decrypt("sensitive.csv.age")
#'
#' # Custom output path
#' file_decrypt("data.txt.age", "recovered_data.txt", key$private)
#' }
#'
#' @export
file_decrypt <- function(input,
                         output,
                         private = NULL) {
    assert_tools()
    if (is.null(private)) {
        private <- readline("Enter private key: ")
        if (nchar(private) == 0) {
            stop("Private key cannot be empty")
        }
        args <- c("--decrypt", "-i", "-")
        stdin_input <- private
    } else if (file.exists(private)) {
        args <- c("--decrypt", "-i", private)
        stdin_input <- NULL
    } else if (grepl("^AGE-SECRET-KEY-1", private)) {
        args <- c("--decrypt", "-i", "-")
        stdin_input <- private
    } else {
        stop("`private` must be a filepath or a private-key string starting with AGE-SECRET-KEY-1")
    }

    args <- c(args, "-o", output, input)

    res <- system2("age",
        args = args,
        input = stdin_input,
        stdout = FALSE,
        stderr = FALSE)
    if (res != 0) stop("age decryption failed (exit code ", res, ")")
    invisible(output)
}

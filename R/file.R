#' Encrypt a file using age
#'
#' Encrypt any file using age encryption with public key(s) or a passphrase.
#' The encrypted file will have a `.age` extension by default.
#'
#' @param input Character string. Path to the file to encrypt.
#' @param output Character string. Path for the encrypted output file. Defaults to `input.age`.
#' @param public Character vector or NULL. Public key(s) for encryption (age recipient identifiers).
#'   If NULL, will prompt for a passphrase instead.
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
#' file_encrypt("sensitive.csv")
#'
#' # Custom output path and ASCII armor
#' file_encrypt("data.txt", "encrypted_data.age", key$public, armor = TRUE)
#' }
#'
#' @export
file_encrypt <- function(input = NULL,
                         output = if (!is.null(input)) paste0(input, ".age") else NULL,
                         public = NULL,
                         overwrite = FALSE,
                         armor = FALSE) {
    assert_age()
    checkmate::assert_flag(overwrite)
    checkmate::assert_file_exists(input)
    checkmate::assert_path_for_output(output, overwrite = overwrite)
    checkmate::assert_character(public, null.ok = TRUE)
    checkmate::assert_flag(armor)
    if (is.null(public)) {
        args <- c("--passphrase", "-o", shQuote(output), shQuote(input))
    } else {
        args <- c("-o", shQuote(output))
        for (recipient in public) {
            args <- c(args, "-r", shQuote(recipient))
        }
        if (armor) args <- c(args, "--armor")
        args <- c(args, shQuote(input))
    }
    res <- system2("age", args)
    if (res != 0) stop("age encryption failed (exit code ", res, ")")
    return(invisible(NULL))
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
#'   - NULL to prompt for passphrase input
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
#' # Decrypt with prompted passphrase
#' file_decrypt("sensitive.csv.age")
#'
#' # Custom output path
#' file_decrypt("data.txt.age", "recovered_data.txt", key$private)
#' }
#'
#' @export
file_decrypt <- function(input = NULL,
                         output = NULL,
                         private = NULL,
                         overwrite = FALSE) {
    assert_age()
    checkmate::assert_file_exists(input)
    checkmate::assert_flag(overwrite)
    checkmate::assert_path_for_output(output, overwrite = overwrite)
    if (!is.null(private)) { # no null.ok in this function
        checkmate::assert_file_exists(private)
    }


    if (!is.null(private)) {
        # Use identity file
        args <- c("-d", "-i", shQuote(private), "-o", shQuote(output), shQuote(input))
        stdin_input <- NULL
    } else {
        # Use passphrase
        args <- c("--decrypt", "--passphrase", "-o", shQuote(output), shQuote(input))
        stdin_input <- NULL
    }

    res <- system2("age",
        args = args,
        input = stdin_input,
        stdout = FALSE,
        stderr = FALSE)

    if (res != 0) stop("age decryption failed (exit code ", res, ")")
    invisible(output)
}

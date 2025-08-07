#' @keywords internal
assert_age <- function() {
    age_available <- nzchar(Sys.which("age"))
    if (age_available) {
        age_available <- tryCatch(
            {
                system("age --version", intern = TRUE, ignore.stdout = TRUE, ignore.stderr = TRUE)
                TRUE
            },
            error = function(e) FALSE)
    }

    if (!age_available) {
        stop("age is not available. Install from https://github.com/FiloSottile/age", call. = FALSE)
    }
}



#' Encrypt a file using age
#'
#' Encrypts a file using the age encryption tool. Can encrypt with public keys
#' (for key-based encryption) or with a passphrase (when no public keys provided).
#' When using passphrase encryption, the user will be prompted to enter a password.
#'
#' @param input Character string, path to the file to encrypt
#' @param output Character string, path for the encrypted output file. 
#'   Defaults to `input` + ".age" extension
#' @param public Character vector of age public keys (recipients). If NULL, 
#'   will use passphrase encryption and prompt for password
#' @param overwrite Logical, whether to overwrite existing output file
#' @param armor Logical, whether to use ASCII armor format (only applies to public key encryption)
#'
#' @return Invisible NULL
#' @export
#'
#' @examples
#' \dontrun{
#' # Encrypt with public key
#' age_encrypt("secret.txt", public = "age1xyz...")
#'
#' # Encrypt with passphrase (will prompt)
#' age_encrypt("secret.txt")
#'
#' # Encrypt with custom output path and armor
#' age_encrypt("secret.txt", "encrypted.age", 
#'             public = "age1xyz...", armor = TRUE)
#' }
age_encrypt <- function(input = NULL,
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
        message("Reminder: Humans are bad at generating secure passphrases.")
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
#' Decrypts a file that was encrypted with age. Can decrypt using a private key file
#' (for key-based decryption) or by prompting for a passphrase (when no private key provided).
#' When using passphrase decryption, the user will be prompted to enter the password.
#'
#' @param input Character string, path to the age-encrypted file to decrypt
#' @param output Character string, path for the decrypted output file
#' @param private Character string, path to the private age key file. If NULL,
#'   will use passphrase decryption and prompt for password
#' @param overwrite Logical, whether to overwrite existing output file
#'
#' @return Invisible path to the output file
#' @export
#'
#' @examples
#' \dontrun{
#' # Decrypt with private key
#' age_decrypt("secret.txt.age", "secret.txt", private = "identity.key")
#'
#' # Decrypt with passphrase (will prompt)
#' age_decrypt("secret.txt.age", "secret.txt")
#' }
age_decrypt <- function(input = NULL,
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
        args <- c("--decrypt", "-o", shQuote(output), shQuote(input))
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

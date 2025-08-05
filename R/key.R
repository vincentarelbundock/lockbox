#' Generate a new age identity (key pair)
#'
#' Create a new age encryption key pair. Keys can be saved to a file or kept in memory.
#' The key pair consists of a public key (for encryption) and a private key (for decryption).
#'
#' @param keyfile Character string or NULL. If provided, saves the private key to this file path.
#'   If NULL, returns both public and private keys in memory without saving to disk.
#'
#' @return A `lockbox_key` object containing:
#'   - `$public`: The public key (age recipient identifier)
#'   - `$private`: The private key (only when `keyfile = NULL`)
#'   - `$created`: Timestamp of key creation
#'
#' @examples
#' \dontrun{
#' # Generate keys in memory
#' key <- key_generate()
#' print(key$public)
#' print(key$private)
#'
#' # Generate and save to file
#' key_generate("my_identity.key")
#' }
#'
#' @export
key_generate <- function(keyfile = NULL) {
    assert_tools()
    if (!is.null(keyfile)) {
        exists <- isTRUE(checkmate::check_file_exists(keyfile))
        if (exists) stop("`keyfile` already exists: ", keyfile)
        key <- system2("age-keygen",
            args = c("-o", shQuote(keyfile)),
            stdout = TRUE, stderr = TRUE)
        key <- list(
            public = key,
            private = key_private(keyfile)
        )
    } else {
        key <- system2("age-keygen", stdout = TRUE, stderr = TRUE)
        key <- list(public = key[1], private = key[4])
    }
    key[["created"]] <- Sys.time()
    key[["public"]] <- sub("Public key: ", "", key[["public"]])
    class(key) <- "lockbox_key"
    return(key)
}


#' Print method for lockbox_key objects
#'
#' @param x A `lockbox_key` object.
#' @export
print.lockbox_key <- function(x, ...) {
    cat("Key created: ", as.character(x[["created"]]), "\n")
    cat("Public key: ", x[["public"]], "\n")
    cat("Private key: AGE-SECRET-KEY-*********", "\n")
}

#' Extract public key from an age identity file
#'
#' Read an age identity file and extract the public key (recipient identifier).
#' The public key can be shared and used by others to encrypt data for you.
#'
#' @param keyfile Character string. Path to the age identity file.
#'
#' @return Character string containing the public key (age recipient identifier).
#'
#' @examples
#' \dontrun{
#' # Extract public key from file
#' public_key <- key_public("my_identity.key")
#' print(public_key)
#' }
#'
#' @export
key_public <- function(keyfile) {
    assert_tools()
    key <- system2("age-keygen",
        args = c("-y", shQuote(keyfile)),
        stdout = TRUE)
    trimmed <- trimws(key[length(key)]) # assumes last line is the public key
    trimmed
}

#' Extract private key from an age identity file
#'
#' Read an age identity file and extract the private key string.
#' The private key is secret and used for decryption.
#'
#' @param keyfile Character string. Path to the age identity file.
#'
#' @return Character string containing the private key (starts with "AGE-SECRET-KEY-1").
#'
#' @examples
#' \dontrun{
#' # Extract private key from file
#' private_key <- key_private("my_identity.key")
#' # Use for decryption
#' secrets <- lockbox_decrypt("secrets.yaml", private = private_key)
#' }
#'
#' @export
key_private <- function(keyfile) {
    assert_tools()
    checkmate::assert_file_exists(keyfile)

    lines <- readLines(keyfile)
    # Find the line that starts with AGE-SECRET-KEY-1
    private_key_line <- grep("^AGE-SECRET-KEY-1", lines, value = TRUE)

    if (length(private_key_line) == 0) {
        stop("No AGE-SECRET-KEY-1 found in file: ", keyfile)
    }

    if (length(private_key_line) > 1) {
        warning("Multiple private keys found, returning the first one")
    }

    trimws(private_key_line[1])
}

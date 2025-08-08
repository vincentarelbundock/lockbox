#' Encrypt a file using age
#'
#' Encrypts a file using the age encryption tool. Can encrypt with public keys
#' (for key-based encryption) or with a passphrase (when no public keys provided).
#' If no public keys are specified, will prompt for a passphrase interactively.
#'
#' @param input Character string, path to the file to encrypt
#' @param output Character string, path for the encrypted output file.
#'   Defaults to `input` + ".age" extension
#' @param public Character vector of age public keys (recipients). If NULL,
#'   will use passphrase encryption and prompt for password.
#' @param armor Logical, whether to use ASCII armor format (only applies to public key encryption)
#'
#' @return Invisible NULL
#' @export
#'
#' @examples
#' \dontrun{
#' # Encrypt with public key
#' file_encrypt("secret.txt", public = "age1xyz...")
#'
#' # Encrypt with passphrase (will prompt)
#' file_encrypt("secret.txt")
#'
#' # Encrypt with custom output path and armor
#' file_encrypt("secret.txt", "encrypted.age",
#'   public = "age1xyz...", armor = TRUE)
#' }
file_encrypt <- function(
    input = NULL,
    output = if (!is.null(input)) paste0(input, ".age") else NULL,
    public = NULL,
    armor = FALSE) {
  checkmate::assert_file_exists(input)
  checkmate::assert_path_for_output(output, overwrite = FALSE)
  checkmate::assert_character(public, null.ok = TRUE)
  checkmate::assert_flag(armor)

  input <- normalizePath(input, mustWork = TRUE)
  output <- normalizePath(output, mustWork = FALSE)

  if (!is.null(public)) {
    # Use public key encryption
    age_encrypt_key(input, output, public, armor)
  } else {
    # Use passphrase encryption - prompt user for passphrase
    passphrase <- getPass::getPass("Enter passphrase for encryption: ")
    if (nchar(passphrase) == 0) {
      stop("Empty passphrase not allowed.", call. = FALSE)
    }
    # Armor is ignored for passphrase encryption
    age_encrypt_passphrase(input, output, passphrase)
  }

  return(invisible(NULL))
}


#' Decrypt an age-encrypted file
#'
#' Decrypts a file that was encrypted with age. Can decrypt using a private key file
#' (for key-based decryption) or with a passphrase (when no private key provided).
#' If no private key is specified, will prompt for a passphrase interactively.
#'
#' @param input Character string, path to the age-encrypted file to decrypt
#' @param output Character string, path for the decrypted output file. If NULL, returns content as string.
#' @param private Character string, path to the private age key file. If NULL,
#'   will use passphrase decryption and prompt for password.
#'
#' @return If output is provided, returns invisible path to the output file. If output is NULL, returns decrypted content as string.
#' @export
#'
#' @examples
#' \dontrun{
#' # Decrypt to file with private key
#' file_decrypt("secret.txt.age", "secret.txt", private = "identity.key")
#'
#' # Decrypt to file with passphrase (will prompt)
#' file_decrypt("secret.txt.age", "secret.txt")
#'
#' # Decrypt to string (no file output)
#' content <- file_decrypt("secret.txt.age", output = NULL, private = "identity.key")
#' content <- file_decrypt("secret.txt.age", output = NULL) # will prompt for passphrase
#' }
file_decrypt <- function(
    input = NULL,
    output = NULL,
    private = NULL) {
  # Input validation
  checkmate::assert_file_exists(input)
  checkmate::assert_character(private, len = 1, null.ok = TRUE)

  # Validate output parameter - never overwrite
  if (!is.null(output)) {
    checkmate::assert_path_for_output(output, overwrite = FALSE)
  }

  # Normalize paths
  input <- normalizePath(input, mustWork = TRUE)

  # Use appropriate Rust function based on authentication method
  if (!is.null(private)) {
    # Use key-based decryption
    checkmate::assert_file_exists(private)
    private <- normalizePath(private, mustWork = TRUE)
    decrypted_bytes <- age_decrypt_key(
      encrypted_file_path = input,
      private_key_path = private
    )
  } else {
    # Use passphrase-based decryption - prompt user for passphrase
    passphrase <- getPass::getPass("Enter passphrase for decryption: ")
    if (nchar(passphrase) == 0) {
      stop("Empty passphrase not allowed.", call. = FALSE)
    }
    decrypted_bytes <- age_decrypt_passphrase(
      encrypted_file_path = input,
      passphrase = passphrase
    )
  }

  # If output is NULL, return content as string (attempt UTF-8 conversion)
  if (is.null(output)) {
    return(rawToChar(decrypted_bytes))
  }

  # Otherwise, write raw bytes to file and return path
  output <- normalizePath(output, mustWork = FALSE)
  writeBin(decrypted_bytes, output)
  invisible(output)
}


#' Generate a new age identity (key pair)
#'
#' Create a new age encryption key pair and save it to a file. The key pair consists
#' of a public key (for encryption) and a private key (for decryption). If the specified
#' key file already exists, the function will error to prevent overwriting.
#'
#' @param keyfile Character string, path where the private key will be saved.
#'   The file will contain both public and private key information.
#'
#' @return A `lockbox_key` object containing:
#'   - `$public`: The public key (age recipient identifier)
#'   - `$created`: Timestamp of key creation
#'
#' @examples
#' \dontrun{
#' # Generate and save new key to file
#' key <- key_generate("my_identity.key")
#' print(key$public)
#' }
#'
#' @export
key_generate <- function(keyfile = NULL) {
  checkmate::assert_path_for_output(keyfile, overwrite = FALSE)
  keyfile <- normalizePath(keyfile, mustWork = FALSE)
  if (isTRUE(checkmate::check_file_exists(keyfile))) {
    stop("Key file already exists. Use key_recipient() to read existing key or choose a different path.", call. = FALSE)
  }
  # Use Rust implementation to generate key
  public_key <- age_generate_key(keyfile)
  attr(public_key, "created") <- Sys.time()
  class(public_key) <- "lockbox_key"
  return(public_key)
}


#' Extract public key (recipient) from existing age key file
#'
#' Read an existing age key file and extract the public key component that can
#' be used as a recipient identifier for encryption.
#'
#' @param keyfile Character string, path to an existing age key file.
#'
#' @return A `lockbox_key` object containing:
#'   - `$public`: The public key (age recipient identifier)
#'
#' @examples
#' \dontrun{
#' # Extract public key from existing key file
#' recipient <- key_recipient("my_identity.key")
#' print(recipient$public)
#' }
#'
#' @export
key_recipient <- function(keyfile = NULL) {
  checkmate::assert_file_exists(keyfile)
  keyfile <- normalizePath(keyfile, mustWork = TRUE)
  # Use Rust implementation to extract public key
  public_key <- age_extract_public_key(keyfile)
  class(public_key) <- "lockbox_key"
  return(public_key)
}


#' Generate a new age identity (key pair) - DEPRECATED
#'
#' @param keyfile Character string, path where the private key will be saved.
#' @return A `lockbox_key` object
#' @export
#' @keywords internal
key_generate.R <- function(keyfile = NULL) {
  .Deprecated("key_generate", package = "lockbox")
  checkmate::assert_path_for_output(keyfile, overwrite = FALSE)
  keyfile <- normalizePath(keyfile, mustWork = FALSE)
  if (isTRUE(checkmate::check_file_exists(keyfile))) {
    message("Key file already exists; not overwriting.")
    return(key_recipient(keyfile))
  } else {
    return(key_generate(keyfile))
  }
}


#' Print method for lockbox_key objects
#'
#' @param x A `lockbox_key` object.
#' @export
print.lockbox_key <- function(x, ...) {
  if (!is.null(attr(x, "created"))) {
    cat("Age key created at", format(attr(x, "created")), "\n")
  }
  cat("Public key: ", x, "\n", sep = "")
  invisible(x)
}

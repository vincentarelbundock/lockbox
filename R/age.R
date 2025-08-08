#' @keywords internal
assert_age <- function() {
  age_available <- nzchar(Sys.which("age"))
  if (age_available) {
    age_available <- tryCatch(
      {
        system(
          "age --version",
          intern = TRUE,
          ignore.stdout = TRUE,
          ignore.stderr = TRUE
        )
        TRUE
      },
      error = function(e) FALSE
    )
  }

  if (!age_available) {
    stop(
      "age is not available. Install from https://github.com/FiloSottile/age",
      call. = FALSE
    )
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
    overwrite = FALSE,
    armor = FALSE) {
  assert_age()
  checkmate::assert_flag(overwrite)
  checkmate::assert_file_exists(input)
  checkmate::assert_path_for_output(output, overwrite = overwrite)
  checkmate::assert_character(public, null.ok = TRUE)
  checkmate::assert_flag(armor)
  input <- normalizePath(input, mustWork = TRUE)
  output <- normalizePath(output, mustWork = FALSE)
  if (is.null(public)) {
    args <- c("--passphrase", "-o", shQuote(output), shQuote(input))
    message("Reminder: Humans are bad at generating secure passphrases.")
  } else {
    args <- c("-o", shQuote(output))
    for (recipient in public) {
      args <- c(args, "-r", shQuote(recipient))
    }
    if (armor) {
      args <- c(args, "--armor")
    }
    args <- c(args, shQuote(input))
  }
  res <- system2("age", args)
  if (res != 0) {
    stop("age encryption failed (exit code ", res, ")")
  }
  return(invisible(NULL))
}


#' Decrypt an age-encrypted file
#'
#' Decrypts a file that was encrypted with age. Can decrypt using a private key file
#' (for key-based decryption) or with a passphrase (for passphrase-based decryption).
#' You must provide either a private key or a passphrase, but not both.
#'
#' @param input Character string, path to the age-encrypted file to decrypt
#' @param output Character string, path for the decrypted output file. If NULL, returns content as string.
#' @param private Character string, path to the private age key file. Cannot be used with passphrase.
#' @param passphrase Character string, passphrase for decryption. Cannot be used with private key.
#' @param overwrite Logical, whether to overwrite existing output file (ignored when output is NULL)
#'
#' @return If output is provided, returns invisible path to the output file. If output is NULL, returns decrypted content as string.
#' @export
#'
#' @examples
#' \dontrun{
#' # Decrypt to file with private key
#' file_decrypt("secret.txt.age", "secret.txt", private = "identity.key")
#'
#' # Decrypt to file with passphrase
#' file_decrypt("secret.txt.age", "secret.txt", passphrase = "mypassword")
#'
#' # Decrypt to string (no file output)
#' content <- file_decrypt("secret.txt.age", output = NULL, private = "identity.key")
#' content <- file_decrypt("secret.txt.age", output = NULL, passphrase = "mypassword")
#' }
file_decrypt <- function(
    input = NULL,
    output = NULL,
    private = NULL,
    passphrase = NULL,
    overwrite = FALSE) {
  # Input validation
  checkmate::assert_file_exists(input)
  checkmate::assert_character(private, len = 1, null.ok = TRUE)
  checkmate::assert_character(passphrase, len = 1, null.ok = TRUE)

  # Validate output parameter
  if (!is.null(output)) {
    checkmate::assert_flag(overwrite)
    checkmate::assert_path_for_output(output, overwrite = overwrite)
  }

  # Validate that exactly one authentication method is provided
  if (is.null(private) && is.null(passphrase)) {
    stop("Either 'private' or 'passphrase' must be provided", call. = FALSE)
  }

  if (!is.null(private) && !is.null(passphrase)) {
    stop("Cannot specify both 'private' and 'passphrase'", call. = FALSE)
  }

  # Normalize paths
  input <- normalizePath(input, mustWork = TRUE)

  if (!is.null(private)) {
    checkmate::assert_file_exists(private)
    private <- normalizePath(private, mustWork = TRUE)
  }

  # Use our Rust function to decrypt to memory
  tryCatch(
    {
      # Decrypt content using our Rust function
      decrypted_content <- age_decrypt(
        encrypted_file_path = input,
        private_key_path = private,
        passphrase = passphrase
      )

      # If output is NULL, return content as string
      if (is.null(output)) {
        return(decrypted_content)
      }

      # Otherwise, write to file and return path
      output <- normalizePath(output, mustWork = FALSE)
      writeLines(decrypted_content, output, sep = "")
      invisible(output)
    },
    error = function(e) {
      stop("age decryption failed: ", e$message, call. = FALSE)
    })
}


#' Generate a new age identity (key pair)
#'
#' Create a new age encryption key pair and save it to a file. The key pair consists
#' of a public key (for encryption) and a private key (for decryption). If the specified
#' key file already exists, the function will return the existing public key without
#' overwriting the file.
#'
#' @param keyfile Character string, path where the private key will be saved.
#'   The file will contain both public and private key information.
#'
#' @return A `lockbox_key` object containing:
#'   - `$public`: The public key (age recipient identifier)
#'   - `$private`: The private key (only for newly created keys)
#'   - `$created`: Timestamp of key creation (only for newly created keys)
#'
#'   If the key file already exists, returns a `lockbox_key` object with only
#'   the `$public` component and displays a message about not overwriting.
#'
#' @examples
#' \dontrun{
#' # Generate and save new key to file
#' key <- key_generate.R("my_identity.key")
#' print(key$public)
#'
#' # If file already exists, returns existing public key without overwriting
#' existing_key <- key_generate.R("my_identity.key")
#' print(existing_key$public) # Shows existing public key
#' }
#'
#' @export
key_generate.R <- function(keyfile = NULL) {
  assert_age()
  checkmate::assert_path_for_output(keyfile, overwrite = TRUE)
  keyfile <- normalizePath(keyfile, mustWork = FALSE)
  if (isTRUE(checkmate::check_file_exists(keyfile))) {
    res <- system2(
      "age-keygen",
      args = c("-y", shQuote(keyfile)),
      stdout = TRUE,
      stderr = TRUE
    )
    out <- list("public" = res)
    class(out) <- "lockbox_key"
    message("Key file already exists; not overwriting.")
    return(out)
  } else {
    args <- c("-o", shQuote(keyfile))
    key <- system2("age-keygen", args = args, stdout = TRUE, stderr = TRUE)
    key <- list(public = key[1], private = key[4])
    key[["created"]] <- Sys.time()
    key[["public"]] <- sub("Public key: ", "", key[["public"]])
    class(key) <- "lockbox_key"
    return(key)
  }
}


#' Print method for lockbox_key objects
#'
#' @param x A `lockbox_key` object.
#' @export
print.lockbox_key <- function(x, ...) {
  if ("created" %in% names(x)) {
    x[["created"]] <- format(x[["created"]], "%Y-%m-%d %H:%M:%S")
    cat("Key created: ", as.character(x[["created"]]), "\n")
  }
  x[["public"]] <- sub("Public key: ", "", x[["public"]])
  cat("Public key: ", paste(x[["public"]], collapse = "\n"), "\n")
  cat("Private key: AGE-SECRET-KEY-*********", "\n")
}

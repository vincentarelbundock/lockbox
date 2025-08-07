#' @keywords internal
assert_sops <- function() {
  sops_available <- nzchar(Sys.which("sops"))
  if (sops_available) {
    sops_available <- tryCatch(
      {
        system(
          "sops --version",
          intern = TRUE,
          ignore.stdout = TRUE,
          ignore.stderr = TRUE
        )
        TRUE
      },
      error = function(e) FALSE
    )
  }

  if (!sops_available) {
    stop(
      "SOPS is not available. Install from https://github.com/mozilla/sops",
      call. = FALSE
    )
  }
}


#' Run SOPS command with proper environment setup
#'
#' Internal helper function to run SOPS commands with appropriate
#' environment variables for age keys and recipients.
#'
#' @param args Character vector of command line arguments to pass to sops
#' @param private Character string, path to private age key file (optional)
#' @param public Character vector of public age recipient keys (optional)
#'
#' @return Character vector of command output
#' @keywords internal
sops_run <- function(args, private = NULL, public = NULL) {
  env_vars <- list()

  if (!is.null(private)) {
    private <- normalizePath(private, mustWork = TRUE)
    env_vars[["SOPS_AGE_KEY_FILE"]] <- private
  }

  if (!is.null(public)) {
    env_vars[["SOPS_AGE_RECIPIENTS"]] <- paste(public, collapse = ",")
  }

  result <- with_env(env_vars, {
    system2("sops", args, stdout = TRUE, stderr = TRUE)
  })

  status <- attr(result, "status")
  if (!is.null(status) && status != 0) {
    if (status == 128) {
      if (!is.null(private) && any(grepl("--decrypt", args))) {
        stop(
          "Failed to decrypt with the provided private key. The key may be incorrect or not authorized for this file.",
          call. = FALSE
        )
      } else {
        stop(
          "SOPS operation failed. This may be due to incorrect keys or permissions.",
          call. = FALSE
        )
      }
    } else {
      stop(
        "SOPS command failed with exit code ",
        status,
        ": ",
        paste(result, collapse = "\n"),
        call. = FALSE
      )
    }
  }

  return(result)
}


#' Extract age recipients from encrypted SOPS file
#'
#' Reads a SOPS-encrypted file and extracts the age recipient public keys
#' that can decrypt the file.
#'
#' @param lockbox Character string, path to the SOPS-encrypted file
#'
#' @return Character vector of age recipient public keys
#' @keywords internal
secrets_recipients <- function(lockbox) {
  checkmate::assert_file_exists(lockbox)
  lockbox <- normalizePath(lockbox, mustWork = TRUE)
  content <- yaml::yaml.load_file(lockbox)
  if (!is.null(content$sops) && !is.null(content$sops$age)) {
    recipients <- sapply(content$sops$age, function(x) x$recipient)
    return(as.character(recipients))
  } else {
    stop("No sops age recipients found in file: ", lockbox, call. = FALSE)
  }
}


#' Encrypt secrets using SOPS
#'
#' Creates or updates a SOPS-managed and age-encrypted file with secrets. For new files,
#' requires public age keys. For existing files, requires the private key
#' to decrypt and re-encrypt with new secrets merged in.
#'
#' @param lockbox Character string, path to the encrypted file to create/update
#' @param secrets Named list of secrets to encrypt (keys become variable names)
#' @param public Character vector of age public keys (required for new files)
#' @param private Character string, path to private key file (required for updates, can be password-protected age file)
#'
#' @return Invisible NULL
#' @export
#'
#' @examples
#' \dontrun{
#' # Generate a key pair
#' key <- key_generate.R("private.key")
#'
#' # Create new encrypted lockbox file
#' secrets <- list(
#'   API_KEY = "your-api-key-here",
#'   DATABASE_URL = "postgresql://user:pass@host:5432/db",
#'   AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
#' )
#' secrets_encrypt(
#'   lockbox = "lockbox.yaml",
#'   secrets = secrets,
#'   public = key$public
#' )
#'
#' # Update existing lockbox file
#' secrets_encrypt(
#'   lockbox = "lockbox.yaml",
#'   secrets = list(API_KEY = "a-new-api-key"),
#'   private = "private.key"
#' )
#' }
secrets_encrypt <- function(
    lockbox = NULL,
    secrets = NULL,
    public = NULL,
    private = NULL) {
  assert_sops()
  sanity_secrets(secrets)
  checkmate::assert_character(
    public,
    unique = TRUE,
    names = "unnamed",
    null.ok = TRUE
  )

  # Check for .yaml extension
  if (tools::file_ext(lockbox) != "yaml") {
    stop("lockbox file must have a .yaml extension", call. = FALSE)
  }

  checkmate::assert_path_for_output(lockbox, overwrite = TRUE)
  lockbox <- normalizePath(lockbox, mustWork = FALSE)

  if (!is.null(private)) {
    checkmate::assert_file_exists(private)
    private <- normalizePath(private, mustWork = TRUE)
  }

  if (isTRUE(checkmate::check_file_exists(lockbox))) {
    if (is.null(private)) {
      stop(
        "You must supply a `private` key location to modify an existing `lockbox`.",
        call. = FALSE
      )
    }
    if (!is.null(public)) {
      stop(
        "You cannot supply a `public` key when modifying an existing `lockbox`. Use `private` only.",
        call. = FALSE
      )
    }
    public <- secrets_recipients(lockbox)
    old_secrets <- secrets_decrypt(lockbox, private = private)
    secrets <- modifyList(old_secrets, secrets)
  } else {
    if (is.null(public)) {
      stop(
        "You must supply `public` keys to create a new `lockbox`.",
        call. = FALSE
      )
    }
  }

  tmp <- tempfile(fileext = ".yaml")
  yaml::write_yaml(secrets, file = tmp)
  on.exit(unlink(tmp), add = TRUE)
  args <- c("--encrypt", "--output", shQuote(lockbox), shQuote(tmp))
  res <- sops_run(args, public = public)

  invisible(NULL)
}


#' Decrypt secrets from SOPS file
#'
#' Decrypts a SOPS-encrypted file and returns the secrets as a named list.
#' Automatically handles password-protected age private key files by prompting
#' for the password when needed.
#'
#' @param lockbox Character string, path to the SOPS-encrypted file
#' @param private Character string, path to private age key file (can be password-protected)
#'
#' @return Named list of decrypted secrets
#' @export
#'
#' @examples
#' \dontrun{
#' # Decrypt with regular private key
#' secrets_decrypt(
#'   lockbox = "lockbox.yaml",
#'   private = "private.key"
#' )
#'
#' # Decrypt with password-protected private key (will prompt for password)
#' secrets_decrypt(
#'   lockbox = "lockbox.yaml",
#'   private = "private.key.age"
#' )
#'
#' # Access individual secrets
#' secrets_decrypt(
#'   lockbox = "lockbox.yaml",
#'   private = "private.key"
#' )$API_KEY
#' }
secrets_decrypt <- function(
    lockbox = NULL,
    private = NULL) {
  assert_sops()

  # Check for .yaml extension
  if (tools::file_ext(lockbox) != "yaml") {
    stop("lockbox file must have a .yaml extension", call. = FALSE)
  }

  checkmate::assert_file_exists(lockbox)
  checkmate::assert_file_exists(private)

  lockbox <- normalizePath(lockbox, mustWork = TRUE)
  private <- normalizePath(private, mustWork = TRUE)

  # Check if private file is a password-protected age file
  if (isTRUE(check_age_file(private))) {
    tf <- tempfile(fileext = ".yaml")
    on.exit(unlink(tf), add = TRUE)
    file_decrypt(input = private, output = tf)
    private <- tf
  }

  args <- c("decrypt", "--input-type", "yaml", shQuote(lockbox))
  res <- sops_run(args, private = private)

  # Check if decryption failed by examining the output
  if (length(res) == 0 || all(nchar(res) == 0)) {
    stop(
      "Decryption returned empty output. The private key may be incorrect or not authorized for this file.",
      call. = FALSE
    )
  }
  res <- yaml::yaml.load(res)
  return(res)
}


#' Export SOPS secrets to environment variables
#'
#' Decrypts secrets from a SOPS file and sets them as environment variables
#' in the current R session. Each secret becomes an environment variable
#' with the same name.
#'
#' @param lockbox Character string, path to the SOPS-encrypted file
#' @param private Character string, path to private age key file (can be password-protected)
#'
#' @return Invisible character vector of exported variable names
#' @export
#'
#' @examples
#' \dontrun{
#' # Export all secrets as environment variables
#' secrets_export(
#'   lockbox = "lockbox.yaml",
#'   private = "private.key"
#' )
#'
#' # Now secrets are available as environment variables
#' Sys.getenv("API_KEY")
#' Sys.getenv("DATABASE_URL")
#' }
secrets_export <- function(
    lockbox = NULL,
    private = NULL) {
  assert_sops()
  checkmate::assert_file_exists(lockbox)
  checkmate::assert_file_exists(private)
  lockbox <- normalizePath(lockbox, mustWork = TRUE)
  private <- normalizePath(private, mustWork = TRUE)

  # Decrypt the secrets and set them as environment variables
  secrets <- secrets_decrypt(lockbox = lockbox, private = private)

  # Set each secret as an environment variable
  for (name in names(secrets)) {
    do.call("Sys.setenv", setNames(list(secrets[[name]]), name))
  }

  # Return the names of the exported variables
  invisible(names(secrets))
}

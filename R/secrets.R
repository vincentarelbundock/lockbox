#' Encrypt secrets using age string encryption (internal helper)
#'
#' Creates or updates a YAML file with secrets where keys are in plain text
#' but values are encrypted using age string encryption. This is a simpler
#' alternative to SOPS that doesn't require external tools.
#'
#' @param lockbox Character string, path to the encrypted file to create/update
#' @param secrets Named list of secrets to encrypt (keys become variable names)
#' @param public Character vector of age public keys (required for new files)
#' @param private Character string, path to private key file (required for updates, can be password-protected age file)
#'
#' @return Invisible NULL
#' @keywords internal
secrets_encrypt_lockbox <- function(
    lockbox = NULL,
    secrets = NULL,
    public = NULL,
    private = NULL) {
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
    # Read existing secrets and merge with new ones
    old_secrets <- secrets_decrypt_lockbox(lockbox, private = private)
    secrets <- modifyList(old_secrets, secrets)

    # Extract public key from existing file for encryption
    existing_data <- yaml::yaml.load_file(lockbox)
    if (is.null(existing_data) || length(existing_data) == 0) {
      stop("Existing lockbox file is empty or invalid", call. = FALSE)
    }
    # For updates, we need to get public key from the private key file
    # Check if private file is a password-protected age file
    if (isTRUE(check_age_file(private))) {
      tf <- tempfile(fileext = ".key")
      on.exit(unlink(tf), add = TRUE)
      file_decrypt(input = private, output = tf)
      public <- key_recipient(tf)
    } else {
      public <- key_recipient(private)
    }
  } else {
    if (is.null(public)) {
      stop(
        "You must supply `public` keys to create a new `lockbox`.",
        call. = FALSE
      )
    }
  }

  # Encrypt all secret values using string_encrypt (uses base64 by default)
  encrypted_secrets <- list()
  for (name in names(secrets)) {
    encrypted_secrets[[name]] <- string_encrypt(
      input = secrets[[name]],
      public = public
    )
  }

  # Add metadata to identify this as a lockbox (non-SOPS) format
  encrypted_secrets$lockbox_created <- Sys.time()
  encrypted_secrets$lockbox_version <- as.character(packageVersion("lockbox"))
  encrypted_secrets$lockbox_recipients <- as.character(public)

  # Write encrypted secrets to YAML file
  yaml::write_yaml(encrypted_secrets, file = lockbox)

  invisible(NULL)
}


#' Decrypt secrets from age string encrypted file (internal helper)
#'
#' Decrypts a YAML file where values were encrypted using age string encryption.
#' Returns the secrets as a named list. Automatically handles password-protected
#' age private key files by prompting for the password when needed.
#'
#' @param lockbox Character string, path to the encrypted YAML file
#' @param private Character string, path to private age key file (can be password-protected)
#'
#' @return Named list of decrypted secrets
#' @keywords internal
secrets_decrypt_lockbox <- function(
    lockbox = NULL,
    private = NULL) {
  # Check for .yaml extension
  if (tools::file_ext(lockbox) != "yaml") {
    stop("lockbox file must have a .yaml extension", call. = FALSE)
  }

  checkmate::assert_file_exists(lockbox)
  checkmate::assert_file_exists(private)

  lockbox <- normalizePath(lockbox, mustWork = TRUE)
  private <- normalizePath(private, mustWork = TRUE)

  # Check if private file is a password-protected age file
  temp_private <- private
  if (isTRUE(check_age_file(private))) {
    tf <- tempfile(fileext = ".key")
    on.exit(unlink(tf), add = TRUE)
    file_decrypt(input = private, output = tf)
    temp_private <- tf
  }

  # Read encrypted secrets from YAML file
  encrypted_secrets <- yaml::yaml.load_file(lockbox)

  if (is.null(encrypted_secrets) || length(encrypted_secrets) == 0) {
    stop("Lockbox file is empty or invalid", call. = FALSE)
  }

  # Filter out metadata fields before decrypting
  metadata_fields <- c("lockbox_created", "lockbox_version", "lockbox_recipients")
  secret_names <- setdiff(names(encrypted_secrets), metadata_fields)

  # Decrypt all secret values using string_decrypt
  decrypted_secrets <- list()
  for (name in secret_names) {
    decrypted_secrets[[name]] <- string_decrypt(
      input = encrypted_secrets[[name]],
      private = temp_private
    )
  }

  return(decrypted_secrets)
}


#' Export age string encrypted secrets to environment variables (internal helper)
#'
#' Decrypts secrets from a YAML file with age string encrypted values and sets
#' them as environment variables in the current R session. Each secret becomes
#' an environment variable with the same name.
#'
#' @param lockbox Character string, path to the encrypted YAML file
#' @param private Character string, path to private age key file (can be password-protected)
#'
#' @return Invisible character vector of exported variable names
#' @keywords internal
secrets_export_lockbox <- function(
    lockbox = NULL,
    private = NULL) {
  checkmate::assert_file_exists(lockbox)
  checkmate::assert_file_exists(private)
  lockbox <- normalizePath(lockbox, mustWork = TRUE)
  private <- normalizePath(private, mustWork = TRUE)

  # Decrypt the secrets and set them as environment variables
  secrets <- secrets_decrypt_lockbox(lockbox = lockbox, private = private)

  # Set each secret as an environment variable
  for (name in names(secrets)) {
    do.call("Sys.setenv", setNames(list(secrets[[name]]), name))
  }

  # Return the names of the exported variables
  invisible(names(secrets))
}


#' Encrypt secrets using automatic format detection
#'
#' Creates or updates a lockbox file with encrypted secrets. Automatically detects
#' whether to use SOPS or the simpler lockbox format based on file contents and
#' available parameters. For new files, uses SOPS if external tools are available,
#' otherwise uses the lockbox format.
#'
#' @param lockbox Character string, path to the encrypted file to create/update
#' @param secrets Named list of secrets to encrypt (keys become variable names)
#' @param public Character vector of age public keys (required for new files)
#' @param private Character string, path to private key file (required for updates, can be password-protected age file)
#' @param sops Logical, whether to use SOPS format. Defaults to FALSE (use built-in lockbox format).
#'
#' @return Invisible NULL
#' @export
#'
#' @examples
#' \dontrun{
#' # Generate a key pair
#' key <- key_generate("private.key")
#'
#' # Create new encrypted lockbox file (auto-detects format)
#' secrets <- list(
#'   API_KEY = "your-api-key-here",
#'   DATABASE_URL = "postgresql://user:pass@host:5432/db"
#' )
#' secrets_encrypt(
#'   lockbox = "lockbox.yaml",
#'   secrets = secrets,
#'   public = key
#' )
#'
#' # Update existing lockbox file (auto-detects format)
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
    private = NULL,
    sops = FALSE) {
  # Validate arguments
  checkmate::assert_flag(sops)
  
  # Check for .yaml extension
  if (tools::file_ext(lockbox) != "yaml") {
    stop("lockbox file must have a .yaml extension", call. = FALSE)
  }

  # Determine format to use
  if (file.exists(lockbox)) {
    # File exists - detect format and use same format
    sops_format <- is_sops(lockbox)
  } else {
    # New file - use the sops parameter (defaults to FALSE for lockbox format)
    sops_format <- sops
  }

  # Dispatch to appropriate implementation
  if (sops_format) {
    secrets_encrypt_sops(
      lockbox = lockbox,
      secrets = secrets,
      public = public,
      private = private
    )
  } else {
    secrets_encrypt_lockbox(
      lockbox = lockbox,
      secrets = secrets,
      public = public,
      private = private
    )
  }
}


#' Decrypt secrets using automatic format detection
#'
#' Decrypts a lockbox file and returns the secrets as a named list.
#' Automatically detects whether the file uses SOPS or lockbox format.
#'
#' @param lockbox Character string, path to the encrypted lockbox file
#' @param private Character string, path to private age key file (can be password-protected)
#'
#' @return Named list of decrypted secrets
#' @export
#'
#' @examples
#' \dontrun{
#' # Decrypt any lockbox file (auto-detects format)
#' secrets_decrypt(
#'   lockbox = "lockbox.yaml",
#'   private = "private.key"
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
  # Detect format and dispatch to appropriate implementation
  if (is_sops(lockbox)) {
    secrets_decrypt_sops(lockbox = lockbox, private = private)
  } else {
    secrets_decrypt_lockbox(lockbox = lockbox, private = private)
  }
}


#' Export secrets to environment variables using automatic format detection
#'
#' Decrypts secrets from a lockbox file and sets them as environment variables
#' in the current R session. Automatically detects whether the file uses SOPS
#' or lockbox format.
#'
#' @param lockbox Character string, path to the encrypted lockbox file
#' @param private Character string, path to private age key file (can be password-protected)
#'
#' @return Invisible character vector of exported variable names
#' @export
#'
#' @examples
#' \dontrun{
#' # Export all secrets as environment variables (auto-detects format)
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
  # Detect format and dispatch to appropriate implementation
  if (is_sops(lockbox)) {
    secrets_export_sops(lockbox = lockbox, private = private)
  } else {
    secrets_export_lockbox(lockbox = lockbox, private = private)
  }
}

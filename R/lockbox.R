#' @keywords internal
.run_sops <- function(args, lockbox = NULL, intern = FALSE) {
  cmd_parts <- c("sops", args)

  if (!is.null(lockbox)) {
    cmd_parts <- c(cmd_parts, shQuote(lockbox))
  }

  cmd <- paste(cmd_parts, collapse = " ")
  system(cmd, intern = intern)
}

#' @keywords internal
.with_sops_key <- function(private, expr) {
  if (is.null(private)) {
    return(expr)
  }

  # Private key is a file path - read the private key
  if (isTRUE(checkmate::check_file_exists(private))) {
    private <- key_private(private)
  }

  # Set environment variable for SOPS
  if (grepl("^AGE-SECRET-KEY-1", private)) {
    prev_key <- Sys.getenv("SOPS_AGE_KEY", unset = NA)
    Sys.setenv(SOPS_AGE_KEY = private)

    # Ensure cleanup happens regardless of success/failure
    on.exit(
      {
        if (is.na(prev_key)) {
          Sys.unsetenv("SOPS_AGE_KEY")
        } else {
          Sys.setenv(SOPS_AGE_KEY = prev_key)
        }
      },
      add = TRUE)
  } else {
    stop("`private` must be a filepath or a private-key string starting with AGE-SECRET-KEY-1")
  }

  expr
}


#' Encrypt secrets to a SOPS lockbox
#'
#' Store secrets in an encrypted YAML file using SOPS and age encryption.
#' If the lockbox file already exists, secrets will be merged with existing ones.
#'
#' @param lockbox Character string. Path to the lockbox YAML file to create or update.
#' @param secrets Named list. Secrets to encrypt, where names are variable names and values are the secret values.
#' @param public Character vector. One or more public keys for encryption (age recipient identifiers).
#' @param private Character string or NULL. Private key required if lockbox already exists (for decryption and merging). Can be a private key string starting with "AGE-SECRET-KEY-1" or path to a key file.
#'
#' @return Invisibly returns NULL.
#'
#' @examples
#' \dontrun{
#' # Generate keys
#' key <- key_generate()
#'
#' # Encrypt secrets
#' secrets <- list(API_KEY = "secret123", DB_PASSWORD = "pass456")
#' lockbox_encrypt("secrets.yaml", secrets, key$public)
#'
#' # Add more secrets to existing lockbox
#' more_secrets <- list(NEW_TOKEN = "token789")
#' lockbox_encrypt("secrets.yaml", more_secrets, key$public, key$private)
#' }
#'
#' @export
lockbox_encrypt <- function(
    lockbox,
    secrets,
    public,
    private = NULL) {
  assert_tools()
  checkmate::assert_string(lockbox)
  checkmate::assert_list(secrets, names = "unique")
  checkmate::assert_character(public, unique = TRUE, names = "unnamed")
  if (!is.null(private)) {
    checkmate::assert_string(private)
  }

  # Sanity check: ensure each secret is a single string
  for (i in seq_along(secrets)) {
    secret_name <- names(secrets)[i]
    secret_value <- secrets[[i]]

    if (!is.character(secret_value) || length(secret_value) != 1) {
      stop("Secret '", secret_name, "' must be a single character string, got: ",
        class(secret_value)[1], " of length ", length(secret_value),
        call. = FALSE)
    }

    if (is.na(secret_value) || nchar(secret_value) == 0) {
      stop("Secret '", secret_name, "' cannot be empty or NA", call. = FALSE)
    }
  }

  if (isTRUE(checkmate::check_file_exists(lockbox, extension = "yaml"))) {
    if (is.null(private)) {
      stop("`private` key is required when lockbox file already exists for decryption and merging", call. = FALSE)
    }
    existing_secrets <- lockbox_decrypt(lockbox, private = private)
    secrets <- utils::modifyList(existing_secrets, secrets)
  }

  tmp <- tempfile(fileext = ".yaml")
  on.exit(unlink(tmp), add = TRUE)

  yaml::write_yaml(secrets, tmp)

  args <- sprintf("--encrypt --output %s --age %s", shQuote(lockbox), paste(public, collapse = ","))
  result <- .run_sops(args, tmp)
  if (result != 0) {
    stop("Failed to encrypt secrets with SOPS")
  }

  invisible(NULL)
}


#' Decrypt secrets from a SOPS lockbox
#'
#' Retrieve and decrypt secrets from an encrypted YAML lockbox file.
#' Can return all secrets or filter to specific secret names.
#'
#' @param lockbox Character string. Path to the lockbox YAML file to decrypt.
#' @param secrets Character vector or NULL. Specific secret names to retrieve. If NULL, returns all secrets.
#' @param private Character string or NULL. Private key for decryption. Can be a private key string starting with "AGE-SECRET-KEY-1" or path to a key file. If NULL, uses default SOPS key resolution.
#'
#' @return Named list of decrypted secrets.
#'
#' @examples
#' \dontrun{
#' # Decrypt all secrets
#' all_secrets <- lockbox_decrypt("secrets.yaml", private = key$private)
#'
#' # Decrypt specific secrets
#' api_key <- lockbox_decrypt("secrets.yaml", secrets = "API_KEY", private = key$private)
#'
#' # Decrypt multiple specific secrets
#' creds <- lockbox_decrypt("secrets.yaml", secrets = c("API_KEY", "PASSWORD"), private = key$private)
#'
#' # Decrypt using key file
#' all_secrets <- lockbox_decrypt("secrets.yaml", private = "identity.key")
#' }
#'
#' @export
lockbox_decrypt <- function(
    lockbox,
    secrets = NULL,
    private = NULL) {
  assert_tools()
  checkmate::assert_file_exists(lockbox, extension = "yaml")
  checkmate::assert_character(secrets, unique = TRUE, names = "unnamed", null.ok = TRUE)
  if (!is.null(private)) {
    checkmate::assert_string(private)
  }

  txt <- .with_sops_key(private, {
    tryCatch(
      {
        .run_sops("-d", lockbox, intern = TRUE)
      },
      error = function(e) {
        stop("Failed to decrypt SOPS lockbox: ", e$message)
      })
  })

  all_secrets <- yaml::yaml.load(paste(txt, collapse = "\n"))

  if (is.null(secrets)) {
    return(all_secrets)
  }

  missing_secrets <- setdiff(secrets, names(all_secrets))
  if (length(missing_secrets) > 0) {
    warning("Secrets not found: ", paste(missing_secrets, collapse = ", "))
  }
  all_secrets[intersect(secrets, names(all_secrets))]
}


#' Export secrets from a SOPS lockbox to environment variables
#'
#' Decrypt all secrets from a lockbox file and export them as environment variables.
#' This allows R packages and scripts to access secrets via Sys.getenv().
#'
#' @param lockbox Character string. Path to the lockbox YAML file.
#' @param private Character string or NULL. Private key for decryption. Can be a private key string starting with "AGE-SECRET-KEY-1" or path to a key file. If NULL, uses default SOPS key resolution.
#'
#' @return Invisibly returns the secrets list.
#'
#' @examples
#' \dontrun{
#' # Export all secrets as environment variables
#' lockbox_export("secrets.yaml", private = key$private)
#'
#' # Now you can access them
#' api_key <- Sys.getenv("API_KEY")
#' db_password <- Sys.getenv("DB_PASSWORD")
#' }
#'
#' @export
lockbox_export <- function(lockbox, private = NULL) {
  assert_tools()
  checkmate::assert_file_exists(lockbox, extension = "yaml")
  if (!is.null(private)) {
    checkmate::assert_string(private)
  }

  secrets <- lockbox_decrypt(lockbox, private = private)
  if (!is.list(secrets)) {
    stop("secrets must be a list")
  }
  invisible(lapply(names(secrets), function(k) {
    if (!is.null(secrets[[k]])) {
      # Create named arguments for Sys.setenv
      args <- list(as.character(secrets[[k]]))
      names(args) <- k
      do.call(Sys.setenv, args)
    }
  }))
  invisible(secrets)
}



# Not sure this works across platforms but it could potentially be useful
# lockbox_edit <- function(lockbox, private = NULL) {
#   assert_tools()
#   checkmate::assert_file_exists(lockbox, extension = "yaml")
#   if (!is.null(private)) {
#     checkmate::assert_string(private)
#   }
#
#   result <- .run_sops("", lockbox)
#   if (result != 0) {
#     warning("Editor exited with non-zero status")
#   }
#
#   invisible(NULL)
# }

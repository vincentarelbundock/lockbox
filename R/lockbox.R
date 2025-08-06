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
.is_pgp_encrypted <- function(lockbox) {
  if (!file.exists(lockbox)) {
    return(FALSE)
  }
  
  content <- readLines(lockbox, warn = FALSE)
  any(grepl("BEGIN PGP MESSAGE", content, fixed = TRUE))
}

#' @keywords internal
.extract_public_keys <- function(lockbox) {
  if (!file.exists(lockbox)) {
    return(NULL)
  }
  
  # Read the raw YAML to extract SOPS metadata
  content <- readLines(lockbox, warn = FALSE)
  yaml_content <- yaml::yaml.load(paste(content, collapse = "\n"))
  
  if (is.null(yaml_content$sops)) {
    return(NULL)
  }
  
  if (.is_pgp_encrypted(lockbox)) {
    # Extract PGP fingerprints
    if (!is.null(yaml_content$sops$pgp)) {
      return(sapply(yaml_content$sops$pgp, function(x) x$fp))
    }
  } else {
    # Extract age recipients
    if (!is.null(yaml_content$sops$age)) {
      return(sapply(yaml_content$sops$age, function(x) x$recipient))
    }
  }
  
  return(NULL)
}



#' Encrypt secrets to a SOPS lockbox
#'
#' Store secrets in an encrypted YAML file using SOPS with age or PGP encryption.
#' If the lockbox file already exists, secrets will be merged with existing ones.
#'
#' @param lockbox Character string. Path to the lockbox YAML file to create or update.
#' @param secrets Named list. Secrets to encrypt, where names are variable names and values are the secret values.
#' @param public Character vector or NULL. One or more public keys for encryption (age recipient identifiers or PGP fingerprints). Required for new lockbox files. If NULL and lockbox exists, public keys will be auto-detected from the existing file.
#' @param private Character string or NULL. Path to identity file required if lockbox already exists (for decryption and merging). Not required for PGP encrypted lockboxes.
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
#' # Add more secrets to existing lockbox (auto-detects public keys)
#' more_secrets <- list(NEW_TOKEN = "token789")
#' lockbox_encrypt("secrets.yaml", more_secrets, private = "identity.key")
#' }
#'
#' @export
lockbox_encrypt <- function(
    lockbox,
    secrets,
    public = NULL,
    private = NULL) {
  assert_sops()
  checkmate::assert_string(lockbox)
  checkmate::assert_list(secrets, names = "unique")
  if (!is.null(public)) {
    checkmate::assert_character(public, unique = TRUE, names = "unnamed")
  }
  checkmate::assert_file_exists(private, null.ok = TRUE)

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

  # Handle existing lockbox files
  if (isTRUE(checkmate::check_file_exists(lockbox, extension = "yaml"))) {
    # Extract existing public keys
    existing_public <- .extract_public_keys(lockbox)
    
    if (is.null(public)) {
      # Auto-detect public keys from existing lockbox
      public <- existing_public
      if (is.null(public)) {
        stop("Could not extract public keys from existing lockbox file", call. = FALSE)
      }
    } else {
      # Validate provided public keys match existing ones
      if (!is.null(existing_public)) {
        if (!identical(sort(public), sort(existing_public))) {
          stop("Provided public keys do not match existing lockbox recipients/fingerprints", call. = FALSE)
        }
      }
    }
    
    # For PGP files, private key is not required
    if (is.null(private) && !.is_pgp_encrypted(lockbox)) {
      stop("`private` key is required when lockbox file already exists for decryption and merging", call. = FALSE)
    }
    existing_secrets <- lockbox_decrypt(lockbox, private = private)
    secrets <- utils::modifyList(existing_secrets, secrets)
  } else {
    # New lockbox file - public keys are required
    if (is.null(public)) {
      stop("`public` keys are required when creating a new lockbox file", call. = FALSE)
    }
  }

  tmp <- tempfile(fileext = ".yaml")
  on.exit(unlink(tmp), add = TRUE)

  yaml::write_yaml(secrets, tmp)

  # Determine if we're using age or PGP keys
  if (any(grepl("^age1", public))) {
    # Age encryption
    assert_age()
    args <- sprintf("--encrypt --output %s --age %s", shQuote(lockbox), paste(public, collapse = ","))
  } else {
    # Assume PGP fingerprints
    args <- sprintf("--encrypt --output %s --pgp %s", shQuote(lockbox), paste(public, collapse = ","))
  }
  
  result <- .run_sops(args, tmp)
  if (result != 0) {
    stop("Failed to encrypt secrets with SOPS")
  }

  invisible(NULL)
}


#' Decrypt secrets from a SOPS lockbox
#'
#' Retrieve and decrypt secrets from an encrypted YAML lockbox file (age or PGP).
#' Can return all secrets or filter to specific secret names.
#'
#' @param lockbox Character string. Path to the lockbox YAML file to decrypt.
#' @param secrets Character vector or NULL. Specific secret names to retrieve. If NULL, returns all secrets.
#' @param private Character string or NULL. Path to identity file for decryption. If NULL, uses default SOPS key resolution. Not required for PGP encrypted lockboxes.
#'
#' @return Named list of decrypted secrets.
#'
#' @examples
#' \dontrun{
#' # Decrypt all secrets
#' all_secrets <- lockbox_decrypt("secrets.yaml", private = "identity.key")
#'
#' # Decrypt specific secrets
#' api_key <- lockbox_decrypt("secrets.yaml", secrets = "API_KEY", private = "identity.key")
#'
#' # Decrypt multiple specific secrets
#' creds <- lockbox_decrypt("secrets.yaml", secrets = c("API_KEY", "PASSWORD"), private = "identity.key")
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
  assert_sops()
  checkmate::assert_file_exists(lockbox, extension = "yaml")
  checkmate::assert_character(secrets, unique = TRUE, names = "unnamed", null.ok = TRUE)
  checkmate::assert_file_exists(private, null.ok = TRUE)

  # For PGP encrypted files, decrypt directly without private key handling
  if (.is_pgp_encrypted(lockbox)) {
    txt <- tryCatch(
      {
        .run_sops("-d", lockbox, intern = TRUE)
      },
      error = function(e) {
        stop("Failed to decrypt SOPS lockbox: ", e$message)
      })
  } else {
    # For age encrypted files, use the identity file directly
    assert_age()
    if (is.null(private)) {
      stop("`private` identity file is required for age-encrypted lockboxes", call. = FALSE)
    }
    
    args <- paste("-d --age-key-file", shQuote(private))
    txt <- tryCatch(
      {
        .run_sops(args, lockbox, intern = TRUE)
      },
      error = function(e) {
        stop("Failed to decrypt SOPS lockbox: ", e$message)
      })
  }

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
#' @param private Character string or NULL. Path to identity file for decryption. If NULL, uses default SOPS key resolution. Not required for PGP encrypted lockboxes.
#'
#' @return Invisibly returns the secrets list.
#'
#' @examples
#' \dontrun{
#' # Export all secrets as environment variables
#' lockbox_export("secrets.yaml", private = "identity.key")
#'
#' # Now you can access them
#' api_key <- Sys.getenv("API_KEY")
#' db_password <- Sys.getenv("DB_PASSWORD")
#' }
#'
#' @export
lockbox_export <- function(lockbox, private = NULL) {
  assert_sops()
  checkmate::assert_file_exists(lockbox, extension = "yaml")
  checkmate::assert_file_exists(private, null.ok = TRUE)

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
#   assert_sops()
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

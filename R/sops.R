#' @keywords internal
assert_sops <- function() {
    sops_available <- nzchar(Sys.which("sops"))
    if (sops_available) {
        sops_available <- tryCatch(
            {
                system("sops --version", intern = TRUE, ignore.stdout = TRUE, ignore.stderr = TRUE)
                TRUE
            },
            error = function(e) FALSE)
    }

    if (!sops_available) {
        stop("SOPS is not available. Install from https://github.com/mozilla/sops", call. = FALSE)
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
                stop("Failed to decrypt with the provided private key. The key may be incorrect or not authorized for this file.", call. = FALSE)
            } else {
                stop("SOPS operation failed. This may be due to incorrect keys or permissions.", call. = FALSE)
            }
        } else {
            stop("SOPS command failed with exit code ", status, ": ", paste(result, collapse = "\n"), call. = FALSE)
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
sops_recipients <- function(lockbox) {
    checkmate::assert_file_exists(lockbox)
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
#' Creates or updates a SOPS-encrypted file with secrets. For new files,
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
#' # Create new encrypted file
#' sops_encrypt(
#'   lockbox = "secrets.yaml",
#'   secrets = list(API_KEY = "secret123"),
#'   public = "age1xyz..."
#' )
#'
#' # Update existing file
#' sops_encrypt(
#'   lockbox = "secrets.yaml", 
#'   secrets = list(NEW_SECRET = "value"),
#'   private = "private.key"
#' )
#' }
sops_encrypt <- function(
    lockbox = NULL,
    secrets = NULL,
    public = NULL,
    private = NULL) {
    # Sanity checks
    assert_sops()
    checkmate::assert_path_for_output(lockbox, overwrite = TRUE)
    checkmate::assert_character(public, unique = TRUE, names = "unnamed", null.ok = TRUE)
    if (!is.null(private)) checkmate::assert_file_exists(private)
    sanity_secrets(secrets)

    if (isTRUE(checkmate::check_file_exists(lockbox))) {
        if (is.null(private)) {
            stop("You must supply a `private` key location to modify an existing `lockbox`.", call. = FALSE)
        }
        if (!is.null(public)) {
            stop("You cannot supply a `public` key when modifying an existing `lockbox`. Use `private` only.", call. = FALSE)
        }
        public <- sops_recipients(lockbox)
        old_secrets <- sops_decrypt(lockbox, private = private)
        secrets <- modifyList(old_secrets, secrets)
    } else {
        if (is.null(public)) {
            stop("You must supply `public` keys to create a new `lockbox`.", call. = FALSE)
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
#' secrets <- sops_decrypt("secrets.yaml", "private.key")
#'
#' # Decrypt with password-protected private key (will prompt for password)
#' secrets <- sops_decrypt("secrets.yaml", "private.key.age")
#'
#' # Access individual secrets
#' api_key <- secrets$API_KEY
#' }
sops_decrypt <- function(
    lockbox = NULL,
    private = NULL) {
    assert_sops()
    checkmate::assert_file_exists(lockbox)
    checkmate::assert_file_exists(private)

    # Check if private file is a password-protected age file
    if (isTRUE(check_age_file(private))) {
        # Decrypt the password-protected age file to a temporary file
        temp_key <- tempfile(fileext = ".key")
        on.exit(unlink(temp_key), add = TRUE)

        age_decrypt(input = private, output = temp_key)
        private <- temp_key
    }

    args <- c("--decrypt", shQuote(lockbox))
    res <- sops_run(args, private = private)

    # Check if decryption failed by examining the output
    if (length(res) == 0 || all(nchar(res) == 0)) {
        stop("Decryption returned empty output. The private key may be incorrect or not authorized for this file.", call. = FALSE)
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
#' sops_export("secrets.yaml", "private.key")
#'
#' # Now secrets are available as environment variables
#' api_key <- Sys.getenv("API_KEY")
#' }
sops_export <- function(
    lockbox = NULL,
    private = NULL) {
    assert_sops()
    checkmate::assert_file_exists(lockbox)
    checkmate::assert_file_exists(private)

    # Decrypt the secrets and set them as environment variables
    secrets <- sops_decrypt(lockbox = lockbox, private = private)

    # Set each secret as an environment variable
    for (name in names(secrets)) {
        do.call("Sys.setenv", setNames(list(secrets[[name]]), name))
    }

    # Return the names of the exported variables
    invisible(names(secrets))
}

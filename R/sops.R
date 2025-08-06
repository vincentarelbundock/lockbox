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


sops_run <- function(args, private = NULL, public = NULL) {
    env_vars <- list()

    if (!is.null(private)) {
        env_vars[["SOPS_AGE_KEY_FILE"]] <- private
    }

    if (!is.null(public)) {
        env_vars[["SOPS_AGE_RECIPIENTS"]] <- paste(public, collapse = ",")
    }

    with_env(env_vars, {
        system2("sops", args, stdout = TRUE, stderr = TRUE)
    })
}


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


sops_decrypt <- function(
    lockbox = NULL,
    private = NULL) {
    assert_sops()
    checkmate::assert_file_exists(lockbox)
    checkmate::assert_file_exists(private)
    args <- c("--decrypt", shQuote(lockbox))
    res <- sops_run(args, private = private)
    res <- yaml::yaml.load(res)
    return(res)
}

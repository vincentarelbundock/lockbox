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
#' @export
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
#' @export
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
        args <- c("--decrypt", "--passphrase", "-o", shQuote(output), shQuote(input))
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

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

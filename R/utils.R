#' @keywords internal
check_tools <- function() {
    sops_available <- nzchar(Sys.which("sops"))
    if (sops_available) {
        sops_available <- tryCatch(
            {
                system("sops --version", intern = TRUE, ignore.stdout = TRUE, ignore.stderr = TRUE)
                TRUE
            },
            error = function(e) FALSE)
    }

    age_available <- nzchar(Sys.which("age"))
    if (age_available) {
        age_available <- tryCatch(
            {
                system("age --version", intern = TRUE, ignore.stdout = TRUE, ignore.stderr = TRUE)
                TRUE
            },
            error = function(e) FALSE)
    }

    if (!sops_available && !age_available) {
        return("Both SOPS and age are not available. Install SOPS from https://github.com/mozilla/sops and age from https://github.com/FiloSottile/age")
    } else if (!sops_available) {
        return("SOPS is not available. Install from https://github.com/mozilla/sops")
    } else if (!age_available) {
        return("age is not available. Install from https://github.com/FiloSottile/age")
    }

    return(TRUE)
}


#' @keywords internal
assert_tools <- function() {
    result <- check_tools()
    if (!isTRUE(result)) {
        stop(result, call. = FALSE)
    }
}

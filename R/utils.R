with_env <- function(env_vars, expr) {
  # Store original values
  original <- lapply(names(env_vars), function(name) {
    current <- Sys.getenv(name, unset = NA)
    if (is.na(current)) NULL else current
  })
  names(original) <- names(env_vars)

  # Ensure restoration happens even if expr fails
  on.exit({
    for (name in names(original)) {
      if (is.null(original[[name]])) {
        Sys.unsetenv(name)
      } else {
        do.call(Sys.setenv, setNames(list(original[[name]]), name))
      }
    }
  })

  # Set new values
  do.call(Sys.setenv, env_vars)

  # Execute expression
  expr
}


sanity_secrets <- function(secrets) {
  checkmate::assert_list(secrets, names = "unique")
  for (s in secrets) {
    if (!is.character(s) || length(s) != 1) {
      stop("All secrets must be single character strings.", call. = FALSE)
    }
  }
}

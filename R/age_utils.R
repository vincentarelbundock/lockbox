#' @keywords internal
check_age_file <- function(path) {
  checkmate::assert_file_exists(path)

  # Read first several bytes
  con <- file(path, "rb")
  on.exit(close(con))

  # First try to read as text lines to check for age header
  seek(con, where = 0, origin = "start")
  lines <- readLines(con, n = 5, warn = FALSE)

  # Common first line in age-encrypted file:
  # age-encryption.org/v1
  if (
    length(lines) >= 1 &&
      grepl("^age-encryption\\.org/v1", lines[1], fixed = FALSE)
  ) {
    return(TRUE)
  }

  # Check for armored header by reading raw bytes and converting safely
  seek(con, where = 0, origin = "start")
  raw_hdr <- readBin(con, what = "raw", n = 256)

  # Convert raw bytes to character, but only up to first null byte to avoid errors
  null_pos <- which(raw_hdr == as.raw(0))[1]
  if (!is.na(null_pos)) {
    raw_hdr <- raw_hdr[1:(null_pos - 1)]
  }

  if (length(raw_hdr) > 0) {
    hdr_text <- suppressWarnings(rawToChar(raw_hdr))
    if (grepl("-----BEGIN AGE ENCRYPTED FILE-----", hdr_text, fixed = TRUE)) {
      return(TRUE)
    }
  }

  return(
    "File does not appear to be age-encrypted (no armor boundary or age header detected)"
  )
}

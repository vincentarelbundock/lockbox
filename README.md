

# lockbox: Simple File Encryption and Secrets Management in R

> Simple file encryption and secret management for R using modern
> cryptographic tools. Provides functions to encrypt/decrypt files with
> ‘age’ and manage secrets in encrypted YAML files with ‘SOPS’. Secrets
> can be easily exported as environment variables for use with APIs and
> services. Supports both file-based and in-memory key management
> workflows.

## Why?

`lockbox` targets two main use cases:

1.  *File Encryption*: R users need an easy way to encrypt and decrypt
    files using simple, modern, secure encryption methods. The package
    supports simple passwords and support key pair workflows.
2.  *Secrets Management*: Many R packages, functions, and services rely
    on environment variables to retrieve users’ API keys, security
    tokens, and assorted secrets (ex: LLM APIs, AWS services, database
    locations, etc.). Users need a secure way to store secrets in an
    encrypted file, and a convenient way to export those secrets as
    environment variables. Although there are solutions for this outside
    R, it is useful to do it within to ensure that variables are
    accessible in the current R session.

## How?

To solve these problems, `lockbox` provides a convenience wrapper around
two command line tools:

1.  The [age](https://age-encryption.org) encryption tool.
2.  The [SOPS](https://getsops.io/) secrets manager.

### `age`: encryption

[age](https://age-encryption.org) is a simple and modern file encryption
tool with small keys, no configuration options, and high security. It is
designed to replace tools like GPG for most file encryption tasks.

There are two main encryption strategies with `age`: passphrase or key
pairs.

The first is simplest. A passphrase is assigned when encrypting the
file. Then, whenever someone wishes to decrypt the file, they are
prompted to supply that same password.

The second strategy relies on a pair of keys:

1.  Public key: a *shareable* string used for encryption.
2.  Private key: a *secret* file for decryption.

This situation illustrates the use of key pairs:

1.  Bob wants to send a secret file to Alice.
2.  Alice shares her public key with Bob.
3.  Bob uses Alice’s public key to encrypt the file.
4.  Bob sends the encrypted file to Alice.
5.  Alice uses her private key to decrypt the file.

Anyone with your public key can encrypt files for you, but only you can
decrypt them with your private key.

### `SOPS`: organize and export secrets

[SOPS](https://github.com/mozilla/sops) is a secrets manager which
`lockbox` uses for two main purposes:

1.  Organize secrets in an encrypted “lockbox” file in YAML format.
2.  Export the secrets held in a lockbox as environment variables, so
    that other R processes and functions can access API keys, security
    tokens, etc.

> [!WARNING]
>
> You must *never* edit your `lockbox.yaml` file manually. Always use
> the provided functions or `sops` to ensure the file remains valid and
> encrypted.

## Installation

To use the `lockbox` package, you must first install the `age` and
`sops` command line tools. Both tools are free and available for
Windows, macOS, and Linux.

- <https://age-encryption.org>
- [SOPS website](https://getsops.io/)

For detailed installation instructions, click on the links above. Most
users will find it easy to install `age` and `SOPS` using a package
manager like [Homebrew (MacOS)](https://brew.sh/) or [Chocolatey
(Windows).](https://chocolatey.org/)

``` sh
# macOS
brew install age sops

# Windows
choco install age.portable
choco install sops

# Linux
# Use your distributions package manager
```

You can install the development version of `lockbox` from Github:

``` r
library(remotes)
install_github("vincentarelbundock/lockbox")
```

## Keys

Our first step is to create a private/public key pair using the
`key_generate()` function. The private key is saved to a file and should
be kept secret. The public key can be shared and is used to encrypt
data.

``` r
library(lockbox)
key <- key_generate.R("private.key")
key
```

    Key created:  2025-08-07 08:42:31 
    Public key:  age1f72e726x6ks4js476dlq75v6z0p364nwas0cv56yp5xv77d4ma2qxazyl9 
    Private key: AGE-SECRET-KEY-********* 

This command created a local “identity file,” which holds both the
public and private keys.

``` r
file.exists("private.key")
```

    [1] TRUE

> [!WARNING]
>
> **Do not share the `private.key` file**. It should be kept secret and
> secure.

## Use-case 1: Encrypting files

`lockbox` can encrypt and decrypt arbitrary files. To illustrate, let’s
create a file with some text in it.

``` r
# write file
cat("Very sensitive data.\n", file = "sensitive.txt")

# make sure we can read it
readLines("sensitive.txt")
```

    [1] "Very sensitive data."

Now, let’s use the public key and the `file_encrypt()` function to
encrypt the file. The `.age` suffix is added automatically to the file
name, and the content becomes gibberish.

``` r
file_encrypt(
  input = "sensitive.txt",
  public = key$public
)

readLines("sensitive.txt.age")
```

    [1] "age-encryption.org/v1"                                                                                                            
    [2] "-> X25519 5fMV2TgYO0wjKxdJmc6Jh8Hoh8eHIBawfdRULYtIaFk"                                                                            
    [3] "NTm+5w9hWIBa4Cln6g5Bl6+ZPVWGcKCBTecYde667t4"                                                                                      
    [4] "--- Sz0W4cXAr0lIV/cQOfzFyVGcxILRBwnJALy7FXLJLag"                                                                                  
    [5] "\xdaS\"'E0\002#\xe4\xf0.|\xc6\"\xe3:\xc3\xecx<~\xb4\xbeii>\xbd㹎@:\xdaW\xc1b\x83\xb2\xaf\xb1\xe0H\xea\xef\xe5^\177\x8b\xc1:a\xa3Z"

Finally, we can decrypt the file using the private key file. The
decrypted content is written to the specified output file.

``` r
file_decrypt(
  input = "sensitive.txt.age",
  output = "sensitive_decrypted.txt",
  private = "private.key"
)

readLines("sensitive_decrypted.txt")
```

    [1] "Very sensitive data."

## Use-case 2: Storing secrets in a `lockbox` and exporting them as environment variables

Several packages and applications require users to export secrets as
environment variables for easy access. For example, you may need to
store a security key to access the API of an LLM provider; the location
of your private database; or credentials to access AWS services.

Generally speaking, we do *not* want to store those secrets in plain
text files. Instead, we can store them in an encrypted YAML file, and
use a helper function to decrypt the file and export environment
variables.

First, we define a named list with the values that we wish to store
securely. Then, we call `secrets_encrypt()` to encrypt those secrets
into our lockbox file. Again, we use the public key for encryption.

``` r
secrets <- list(
  API_KEY = "your-api-key-here",
  DATABASE_URL = "postgresql://user:pass@host:5432/db",
  AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
)

secrets_encrypt(
  lockbox = "lockbox.yaml",
  secrets = secrets,
  public = key$public
)
```

## Retrieving secrets from a `lockbox`

Now, we can retrieve all secrets using our private key file.

``` r
secrets_decrypt(
  lockbox = "lockbox.yaml",
  private = "private.key"
)
```

    $API_KEY
    [1] "your-api-key-here"

    $DATABASE_URL
    [1] "postgresql://user:pass@host:5432/db"

    $AWS_ACCESS_KEY_ID
    [1] "AKIAIOSFODNN7EXAMPLE"

## Modifying secrets in a `lockbox`

To modify existing secrets or to add new ones, we can simply call
`secrets_encrypt()` again. In this case, however, we need to supply the
`private` key file because modifying requires us to read the existing
secrets.

``` r
secrets_encrypt(
  lockbox = "lockbox.yaml",
  secrets = list("API_KEY" = "a-new-api-key"),
  private = "private.key"
)
```

We see that the `API_KEY` value has indeed been updated.

``` r
secrets_decrypt(
  lockbox = "lockbox.yaml",
  private = "private.key")$API_KEY
```

    [1] "a-new-api-key"

## Exporting secrets as environment variables

Finally, we can export all secrets from the lockbox file as environment
variables. This is useful when running applications that rely on
environment variables for configuration.

``` r
secrets_export(
  lockbox = "lockbox.yaml",
  private = "private.key"
)
```

And we see that the secrets are indeed available in the environment.

``` r
Sys.getenv("API_KEY")
```

    [1] "a-new-api-key"

``` r
Sys.getenv("DATABASE_URL")
```

    [1] "postgresql://user:pass@host:5432/db"

## Enhanced Security: Encrypting Your Private Key

For even more security, you can encrypt your private key file itself
using a passphrase. This adds an extra layer of protection - even if
someone gains access to your key file, they would need to know the
passphrase to use it.

#### Step 1: Encrypt the private key with a passphrase.

``` r
file_encrypt(
  input = "private.key",
  output = "private.key.age"
)
# You will be prompted to enter a secure passphrase
```

When you run this command, you’ll be prompted to enter a passphrase.
Ideally, you should leave the field blank to use the randomly-generated
passphrase supplied by `age`. Otherwise, make sure you choose a strong
passphrase.

#### Step 2: Remove the unencrypted key file.

``` r
unlink("private.key")
```

#### Step 3: Use the password-protected key file.

Now you can use your password-protected key file with all the same
functions. The lockbox package will automatically detect that it’s an
encrypted key file and prompt you for the passphrase when needed.

``` r
secrets_decrypt(
  lockbox = "lockbox.yaml",
  private = "private.key.age"
)
# You will be prompted for your passphrase

secrets_export(
  lockbox = "lockbox.yaml",
  private = "private.key.age"
)
# You will be prompted for your passphrase
```

## Security Considerations

> [!WARNING]
>
> **Temporary File Handling**
>
> There are two cases where `lockbox` creates temporary files with
> sensitive data:
>
> 1.  When the `private` key used in `secrets_decrypt()` or
>     `file_decrypt()` is itself passphrase-encrypted.
> 2.  When calling `secrets_encrypt()` to modify an existing `lockbox`
>     file.
>
> In both cases, a file is written to disk at `tempfile()`, and is
> automatically deleted using `on.exit()` and `unlink()` to ensure
> cleanup on function exit even if an error occurs.
>
> While this approach follows R best practices for temporary file
> handling, users with heightened security requirements may prefer to
> run `age` and `sops` directly from the command line to maintain full
> control over key file handling.

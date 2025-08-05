

# lockbox: Modern Encryption for R

## Why

`lockbox` addresses two main use cases:

1.  *File Encryption*: R users need an easy to encrypt and decrypt files
    using modern, secure encryption methods.
2.  *Secret Management*: Many R packages and services rely on
    environment variables for API keys and security tokens (LLM APIs,
    AWS S3, databases, etc.). Users need a secure way to store secrets
    in an encrypted file, and easily export them to the environment.

## How?

This package provides wrapper to two command line tools:
[age](https://age-encryption.org) encryption and
[SOPS](https://getsops.io/) secrets manager.

### `age` encryption

[age](https://age-encryption.org) is a simple, modern file encryption
tool with small keys, no configuration options, and high security. It’s
designed to replace tools like GPG for file encryption.

Modern encryption uses key pairs composed of:

1.  *Public key* (shareable): for encryption
2.  *Private key* (secrete): for decryption

These keys can be used in this workflow:

1.  Bob wants to send Alice a secret file.
2.  Alice shares her public key with Bob.
3.  Bob uses Alice’s public key to encrypt the file.
4.  Bob sends the encrypted file to Alice.
5.  Alice uses her private key to decrypt the file.

Anyone with your public key can encrypt files for you, but only you can
decrypt them with your private key.

### `SOPS` (Secrets OPerationS)

In this package, [SOPS](https://github.com/mozilla/sops) is used for two
purposes:

1.  Store secrets in an encrypted “lockbox” file in YAML format.
2.  Retrieve secrets from the lockbox and export them as environment
    variables.

> **Warning**
>
> You must *never* edit your `lockbox.yaml` file manually. Always use
> the provided functions or `sops` to ensure the file remains valid and
> encrypted.

## Installation

To use the `lockbox` package, you must first install the `age` and
`sops` command line tools. Both tools are free and available on Windows,
macOS, and Linux.

You can find installation instructions on their respective websites:

-   <https://age-encryption.org>
-   [SOPS website](https://getsops.io/)

Then, you can install `lockbox` from Github:

``` r
remotes::install_github("vincentarelbundock/lockbox")
```

## Tutorial

### Keys

First, we create a private and a public key pair using the
`key_generate()` function. The private key is saved to a file and should
be kept secret. The public key can be shared and is used to encrypt
data.

``` r
library(lockbox)
key <- key_generate("identity.key")
key
```

    Key created:  2025-08-05 16:31:11.365168 
    Public key:  age1g9hc4q6jmyluvgvg4c2qwdy3gqjc6enla0p3lew6qz88fukyj49s9xfmmf 
    Private key: AGE-SECRET-KEY-********* 

This command also wrote a local “identity file” with the given name,
which holds both the public and private keys.

``` r
file.exists("identity.key")
```

    [1] TRUE

Sometimes, it is useful to manipulate the keys programmatically. We can
access them from the `key` object created above, or read them from the
identity file using helper functions.

``` r
key$public
```

    [1] "age1g9hc4q6jmyluvgvg4c2qwdy3gqjc6enla0p3lew6qz88fukyj49s9xfmmf"

``` r
key_private("identity.key")
```

    [1] "AGE-SECRET-KEY-1V3CDSQ47QY3ARVPXU4TPH2MLAW62Q05HWDXS0H36MXPC5E6VNQPSDRARFX"

> **Warning**
>
> The `identity.key` file contains your private key. **Do not share this
> file**. It should be kept secret and secure.

### Use-case 1: Encrypting files

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
encrypt the file. A `.age` suffix, and the content becomes unreadable.

``` r
file_encrypt(
  input = "sensitive.txt",
  public = key$public
)

readLines("sensitive.txt.age")
```

    [1] "age-encryption.org/v1"                                                                                                              
    [2] "-> X25519 Kgik1EsyKApYQ1Es/LgMyclHn9C5jTmTHs/EPeM2pgQ"                                                                              
    [3] "MRNWkQHU/xpmzg+m0MGS8Tg8qgnr56HJMxVDaHityoY"                                                                                        
    [4] "--- vf7e9hSVORLDY9YgpBoUWhD9cf7IKGaiNE2dR2WkgAU"                                                                                    
    [5] "Z\xee7\xee\x99\xcb\xf6h\xcb\xdd\xc3\xfci\xa7\x8c9\xedq\xedB\xd8\xda\xebų\177;\v\x9cu\xa6\xc1=pObC(\xdfdF\b\xed٘b\xa6\002t\t~\xef\xc2"

Finally, we can decrypt the file using the private key. The decrypted
content is written to the `output` file or returned as a character
vector if `output` is omitted.

``` r
file_decrypt(
  input = "sensitive.txt.age",
  output = "sensitive_decrypted.txt",
  private = key$private
)

readLines("sensitive_decrypted.txt")
```

    [1] "Very sensitive data."

### Use-case 2: Storing secrets in a `lockbox` and exporting them as environment variables

Several packages and application require users to export secrets as
environment variables for easy access. *We do not want to store these
secrets in plain text files.* Instead, we can store them in an encrypted
YAML file, and use a helper function to decrypt the file and export
environment variables.

For example, you need to store a security to access an API, the location
of your private database, and some credentials to access AWS services.
First, we define a named list with the values that we wish to store
securely.

Then, we call `lockbox_encrypt()` to encrypt those secrets into our
lockbox file. Again, we use the public key for encryption.

``` r
secrets <- list(
  API_KEY = "your-api-key-here",
  DATABASE_URL = "postgresql://user:pass@host:5432/db",
  AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
)

lockbox_encrypt(
  lockbox = "lockbox.yaml",
  secrets = secrets,
  public = key$public
)
```

### Retrieving secrets from a `lockbox`

Now, we can retreive a few secrets using our private key.

``` r
lockbox_decrypt(
  lockbox = "lockbox.yaml",
  secrets = c("API_KEY", "DATABASE_URL"),
  private = key$private
)
```

    $API_KEY
    [1] "your-api-key-here"

    $DATABASE_URL
    [1] "postgresql://user:pass@host:5432/db"

Or all secrets at once by omitting the `secrets` argument:

``` r
lockbox_decrypt(
  lockbox = "lockbox.yaml",
  private = key$private
)
```

    $API_KEY
    [1] "your-api-key-here"

    $DATABASE_URL
    [1] "postgresql://user:pass@host:5432/db"

    $AWS_ACCESS_KEY_ID
    [1] "AKIAIOSFODNN7EXAMPLE"

### Exporting secrets as environment variables

Finally, we can export all secrets from the lockbox file as environment
variables. This is useful for applications that rely on environment
variables for configuration.

``` r
lockbox_export(
  lockbox = "lockbox.yaml",
  private = key$private
)
```

And we see that the secrets are indeed available in the environment.

``` r
Sys.getenv("API_KEY")
```

    [1] "your-api-key-here"

``` r
Sys.getenv("DATABASE_URL")
```

    [1] "postgresql://user:pass@host:5432/db"

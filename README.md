

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

> [!WARNING]
>
> You must *never* edit your `lockbox.yaml` file manually. Always use
> the provided functions or `sops` to ensure the file remains valid and
> encrypted.

## Installation

To use the `lockbox` package, you must first install the `age` and
`sops` command line tools. Both tools are free and available on Windows,
macOS, and Linux.

You can find installation instructions on their respective websites:

- <https://age-encryption.org>
- [SOPS website](https://getsops.io/)

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

    Key created:  2025-08-06 20:20:30.458858 
    Public key:  age15tux9ausfhhag5rl95kchng7m83t4z0qln7yq5e664qdpnup7cxs53kugu 
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

    [1] "age15tux9ausfhhag5rl95kchng7m83t4z0qln7yq5e664qdpnup7cxs53kugu"

``` r
key_private("identity.key")
```

    [1] "AGE-SECRET-KEY-1GS63VF2L9M2DCTCTJRCGSJNREZTSYHF7GVL4U8CZFX0FY7LSPT2QA3GKE5"

> [!WARNING]
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

Now, let’s use the public key and the `age_encrypt()` function to
encrypt the file. A `.age` suffix is added, and the content becomes
unreadable.

``` r
age_encrypt(
  input = "sensitive.txt",
  public = key$public
)

readLines("sensitive.txt.age")
```

    [1] "age-encryption.org/v1"                                                                                                            
    [2] "-> X25519 eKmns5bkZa6y97rzIm+GzqKoGU2muRzvIjbcPLlaVGE"                                                                            
    [3] "Yr/Ocq+bfOkWu/ZdLjuQ7TOQaKdYAwfGxgRr23vk4fg"                                                                                      
    [4] "--- Ia/WWNff9iS5pBaEaHmvnGL2EAqG7hPVDzr9gIfD+M8"                                                                                  
    [5] "\xf7\xafx\xd2l\xc18\xc2\026\032\b'\026\xed\xf4\xeeԁ\xa8\xac\x92FCI\xd8\023Ic9V\xab\001\x9a\xdd\xdfJ\xa98\x99\xe3\xc7\u05cb\xe9t\\"
    [6] "\x98\x81a\f\xeb\xd2"                                                                                                              

Finally, we can decrypt the file using the private key file. The
decrypted content is written to the specified output file.

``` r
age_decrypt(
  input = "sensitive.txt.age",
  output = "sensitive_decrypted.txt",
  private = "identity.key"
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

Then, we call `sops_encrypt()` to encrypt those secrets into our lockbox
file. Again, we use the public key for encryption.

``` r
secrets <- list(
  API_KEY = "your-api-key-here",
  DATABASE_URL = "postgresql://user:pass@host:5432/db",
  AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
)

sops_encrypt(
  lockbox = "lockbox.yaml",
  secrets = secrets,
  public = key$public
)
```

### Retrieving secrets from a `lockbox`

Now, we can retrieve all secrets using our private key file.

``` r
sops_decrypt(
  lockbox = "lockbox.yaml",
  private = "identity.key"
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
sops_export(
  lockbox = "lockbox.yaml",
  private = "identity.key"
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

## Enhanced Security: Encrypting Your Private Key

For even more security, you can encrypt your private key file itself
using a passphrase. This adds an extra layer of protection - even if
someone gains access to your key file, they would need to know the
passphrase to use it.

### Step 1: Encrypt the private key with a passphrase

``` r
# Encrypt the identity key file with a passphrase
age_encrypt(
  input = "identity.key",
  output = "identity.key.age"
)
# You will be prompted to enter a secure passphrase
```

When you run this command, you’ll be prompted to enter a passphrase.
Choose a strong, memorable passphrase.

### Step 2: Remove the unencrypted key file

``` r
# Remove the original unencrypted key file for security
unlink("identity.key")
```

### Step 3: Use the password-protected key file

Now you can use your password-protected key file with all the same
functions. The lockbox package will automatically detect that it’s an
encrypted key file and prompt you for the passphrase when needed.

``` r
# Decrypt secrets using the password-protected key
# You will be prompted for your passphrase
sops_decrypt(
  lockbox = "lockbox.yaml",
  private = "identity.key.age"
)

# Export secrets using the password-protected key
sops_export(
  lockbox = "lockbox.yaml",
  private = "identity.key.age"
)
```

This approach provides **defense in depth**: 1. Your secrets are
encrypted with SOPS/age 2. Your private key itself is also encrypted
with a passphrase 3. Even if someone accesses your files, they need both
the key file AND the passphrase

> [!TIP]
>
> **Best Practice**: Store your password-protected key file
> (`identity.key.age`) in a secure location, and use a strong, unique
> passphrase that you don’t use elsewhere.

## Security Considerations

> [!WARNING]
>
> **Temporary File Handling**
>
> When using password-protected private key files (`.age` files),
> `lockbox` temporarily decrypts these keys to disk using `tempfile()`
> so that SOPS can read them. These temporary files are automatically
> deleted using `on.exit()` to ensure cleanup even if an error occurs.
>
> While this approach follows R best practices for temporary file
> handling, users with heightened security requirements may prefer to
> run `age` and `sops` commands directly from the command line to
> maintain full control over key file handling.
>
> For most users, the temporary file approach provides a good balance of
> security and usability.

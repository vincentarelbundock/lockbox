// Bridge between Rust and R for age encryption/decryption functionality
use extendr_api::prelude::*;
use std::io::Read;
use std::str::FromStr;
use age::secrecy::ExposeSecret;

/// Decrypt file content using identities and return as bytes
/// 
/// This helper function handles both ASCII-armored and binary age files,
/// decrypts them, and returns the content as raw bytes.
fn decrypt_content<'a, I>(file_content: &[u8], identities: I) -> Result<Vec<u8>>
where
    I: Iterator<Item = &'a dyn age::Identity>,
{
    use age::armor::ArmoredReader;
    use age::Decryptor;
    use std::io::Cursor;

    let mut decrypted_reader: Box<dyn Read> = if file_content.starts_with(b"-----BEGIN AGE ENCRYPTED FILE-----") {
        // Handle ASCII-armored files
        let cursor = Cursor::new(file_content);
        let armored_reader = ArmoredReader::new(cursor);
        let decryptor = Decryptor::new(armored_reader)
            .map_err(|e| Error::Other(format!("Failed to create decryptor: {}", e)))?;
        
        Box::new(decryptor.decrypt(identities)
            .map_err(|e| Error::Other(format!("Failed to decrypt: {}", e)))?)
    } else {
        // Handle binary age files
        let cursor = Cursor::new(file_content);
        let decryptor = Decryptor::new(cursor)
            .map_err(|e| Error::Other(format!("Failed to create decryptor: {}", e)))?;
        
        Box::new(decryptor.decrypt(identities)
            .map_err(|e| Error::Other(format!("Failed to decrypt: {}", e)))?)
    };

    let mut decrypted_content = Vec::new();
    decrypted_reader.read_to_end(&mut decrypted_content)
        .map_err(|e| Error::Other(format!("Failed to read decrypted content: {}", e)))?;

    Ok(decrypted_content)
}


/// Parse age identities from a private key file content
/// 
/// This helper function reads through each line of a key file and extracts
/// all valid age secret keys, returning them as boxed Identity trait objects.
fn parse_identities_from_key_file(key_content: &str) -> Result<Vec<Box<dyn age::Identity>>> {
    let mut identities: Vec<Box<dyn age::Identity>> = Vec::new();
    
    for line in key_content.lines() {
        if line.starts_with("AGE-SECRET-KEY-") {
            // Parse x25519 private key from the line
            let identity = age::x25519::Identity::from_str(line)
                .map_err(|e| Error::Other(format!("Failed to parse identity: {}", e)))?;
            identities.push(Box::new(identity) as Box<dyn age::Identity>);
        }
    }

    if identities.is_empty() {
        return Err(Error::Other("No valid age identities found".to_string()));
    }

    Ok(identities)
}

/// Decrypt an age-encrypted file using a passphrase
/// 
/// This function handles both ASCII-armored and binary age files encrypted with passphrases.
/// It reads the entire file into memory, detects the format, and returns the decrypted content as raw bytes.
/// @keywords internal
/// @noRd
#[extendr]
fn age_decrypt_with_passphrase(encrypted_file_path: &str, passphrase: &str) -> Result<Raw> {
    use age::secrecy::SecretString;
    use std::iter;

    // Read the entire encrypted file into memory
    let file_content = std::fs::read(encrypted_file_path)
        .map_err(|_| Error::Other("Failed to read encrypted file".to_string()))?;

    // Create scrypt identity from passphrase for secure decryption
    let secret_pass = SecretString::from(passphrase.to_owned());
    let identity = age::scrypt::Identity::new(secret_pass);
    
    // Decrypt and return content using the passphrase identity
    let decrypted_bytes = decrypt_content(&file_content, iter::once(&identity as _))?;
    Ok(Raw::from_bytes(&decrypted_bytes))
}

/// Decrypt an age-encrypted file using a private key
/// 
/// This function handles both ASCII-armored and binary age files encrypted with public keys.
/// It reads the private key file, parses all identities, and returns the decrypted content as raw bytes.
/// @keywords internal
/// @noRd
#[extendr]
fn age_decrypt_with_key(encrypted_file_path: &str, private_key_path: &str) -> Result<Raw> {
    // Read the encrypted file and private key file
    let file_content = std::fs::read(encrypted_file_path)
        .map_err(|_| Error::Other("Failed to read encrypted file".to_string()))?;

    let key_content = std::fs::read_to_string(private_key_path)
        .map_err(|_| Error::Other("Failed to read private key file".to_string()))?;

    // Parse all age identities from the key file
    let identities = parse_identities_from_key_file(&key_content)?;
    
    // Decrypt and return content using all available identities
    let decrypted_bytes = decrypt_content(&file_content, identities.iter().map(|i| i.as_ref()))?;
    Ok(Raw::from_bytes(&decrypted_bytes))
}

/// Generate a new age key pair and save to file
/// 
/// This function generates a new x25519 key pair, writes it to the specified file path,
/// and returns the public key string. Assumes the file path is valid and writable.
/// @keywords internal
/// @noRd
#[extendr]
fn age_generate_key(key_file_path: &str) -> Result<String> {
    use std::io::Write;
    
    // Generate a new x25519 identity (private key)
    let identity = age::x25519::Identity::generate();
    
    // Get the corresponding recipient (public key)
    let recipient = identity.to_public();
    
    // Format the private key for writing to file
    let private_key_line = format!("# created: {}\n# public key: {}\n{}\n",
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"),
        recipient,
        identity.to_string().expose_secret()
    );
    
    // Write the private key to the specified file
    let mut file = std::fs::File::create(key_file_path)
        .map_err(|_| Error::Other("Failed to create key file".to_string()))?;
    
    file.write_all(private_key_line.as_bytes())
        .map_err(|_| Error::Other("Failed to write key file".to_string()))?;
    
    // Return the public key as a string
    Ok(recipient.to_string())
}

/// Extract public key from an existing age key file
/// 
/// This function reads an age identity file and extracts the public key
/// (recipient identifier) from the first valid identity found.
/// @keywords internal
/// @noRd
#[extendr]
fn age_extract_public_key(key_file_path: &str) -> Result<String> {
    // Read the key file content
    let key_content = std::fs::read_to_string(key_file_path)
        .map_err(|_| Error::Other("Failed to read key file".to_string()))?;

    // Use the existing parse function to validate the file and get identities
    let _identities = parse_identities_from_key_file(&key_content)?;
    
    // Extract public key from the first valid identity line
    for line in key_content.lines() {
        if line.starts_with("AGE-SECRET-KEY-") {
            let identity = age::x25519::Identity::from_str(line)
                .map_err(|e| Error::Other(format!("Failed to parse identity: {}", e)))?;
            let recipient = identity.to_public();
            return Ok(recipient.to_string());
        }
    }
    
    Err(Error::Other("No valid age identities found".to_string()))
}

/// Encrypt a file using age with public keys
/// 
/// This function encrypts a file using one or more age public keys (recipients).
/// Supports both ASCII-armored and binary output formats.
/// @keywords internal
/// @noRd
#[extendr]
fn age_encrypt_key(input_file_path: &str, output_file_path: &str, recipients: Vec<String>, armor: bool) -> Result<()> {
    use age::armor::ArmoredWriter;
    use std::io::{BufWriter, Write};
    
    // Parse recipients
    let mut parsed_recipients = Vec::new();
    for recipient_str in recipients {
        let recipient = recipient_str.parse::<age::x25519::Recipient>()
            .map_err(|e| Error::Other(format!("Invalid recipient '{}': {}", recipient_str, e)))?;
        parsed_recipients.push(Box::new(recipient) as Box<dyn age::Recipient>);
    }
    
    if parsed_recipients.is_empty() {
        return Err(Error::Other("At least one recipient is required".to_string()));
    }
    
    // Read input file
    let input_data = std::fs::read(input_file_path)
        .map_err(|_| Error::Other("Failed to read input file".to_string()))?;
    
    // Create encryptor
    let encryptor = age::Encryptor::with_recipients(parsed_recipients.iter().map(|r| r.as_ref()))
        .map_err(|e| Error::Other(format!("Failed to create encryptor: {}", e)))?;
    
    // Create output file
    let output_file = std::fs::File::create(output_file_path)
        .map_err(|_| Error::Other("Failed to create output file".to_string()))?;
    
    // Wrap output writer based on armor setting
    let mut writer: Box<dyn Write> = if armor {
        use age::armor::Format;
        Box::new(ArmoredWriter::wrap_output(BufWriter::new(output_file), Format::AsciiArmor)
            .map_err(|e| Error::Other(format!("Failed to create armored writer: {}", e)))?)
    } else {
        Box::new(BufWriter::new(output_file))
    };
    
    // Encrypt and write
    let mut encrypted_writer = encryptor.wrap_output(&mut writer)
        .map_err(|e| Error::Other(format!("Failed to wrap output for encryption: {}", e)))?;
    
    encrypted_writer.write_all(&input_data)
        .map_err(|e| Error::Other(format!("Failed to write encrypted data: {}", e)))?;
    
    encrypted_writer.finish()
        .map_err(|e| Error::Other(format!("Failed to finalize encryption: {}", e)))?;
    
    writer.flush()
        .map_err(|e| Error::Other(format!("Failed to flush output: {}", e)))?;
    
    Ok(())
}

/// Encrypt a file using age with a passphrase
/// 
/// This function encrypts a file using a passphrase-based encryption.
/// @keywords internal
/// @noRd
#[extendr]
fn age_encrypt_passphrase(input_file_path: &str, output_file_path: &str, passphrase: &str) -> Result<()> {
    use age::secrecy::SecretString;
    use std::io::{BufWriter, Write};
    
    // Create scrypt encryptor from passphrase
    let secret_pass = SecretString::from(passphrase.to_owned());
    let encryptor = age::Encryptor::with_user_passphrase(secret_pass);
    
    // Read input file
    let input_data = std::fs::read(input_file_path)
        .map_err(|_| Error::Other("Failed to read input file".to_string()))?;
    
    // Create output file
    let output_file = std::fs::File::create(output_file_path)
        .map_err(|_| Error::Other("Failed to create output file".to_string()))?;
    
    let mut writer = BufWriter::new(output_file);
    
    // Encrypt and write
    let mut encrypted_writer = encryptor.wrap_output(&mut writer)
        .map_err(|e| Error::Other(format!("Failed to wrap output for encryption: {}", e)))?;
    
    encrypted_writer.write_all(&input_data)
        .map_err(|e| Error::Other(format!("Failed to write encrypted data: {}", e)))?;
    
    encrypted_writer.finish()
        .map_err(|e| Error::Other(format!("Failed to finalize encryption: {}", e)))?;
    
    writer.flush()
        .map_err(|e| Error::Other(format!("Failed to flush output: {}", e)))?;
    
    Ok(())
}

/// Encrypt a string using age with public keys
/// 
/// This function encrypts a string using one or more age public keys (recipients).
/// Returns the encrypted content as a base64-encoded string or ASCII armor.
/// @keywords internal
/// @noRd
#[extendr]
fn age_encrypt_string_with_key(input_string: &str, recipients: Vec<String>, armor: bool) -> Result<String> {
    use age::armor::ArmoredWriter;
    use std::io::Write;
    
    // Parse recipients (reuse logic from age_encrypt_key)
    let mut parsed_recipients = Vec::new();
    for recipient_str in recipients {
        let recipient = recipient_str.parse::<age::x25519::Recipient>()
            .map_err(|e| Error::Other(format!("Invalid recipient '{}': {}", recipient_str, e)))?;
        parsed_recipients.push(Box::new(recipient) as Box<dyn age::Recipient>);
    }
    
    if parsed_recipients.is_empty() {
        return Err(Error::Other("At least one recipient is required".to_string()));
    }
    
    // Create encryptor (reuse from age_encrypt_key)
    let encryptor = age::Encryptor::with_recipients(parsed_recipients.iter().map(|r| r.as_ref()))
        .map_err(|e| Error::Other(format!("Failed to create encryptor: {}", e)))?;
    
    // Use in-memory buffer instead of file
    let mut output_buffer = Vec::new();
    
    if armor {
        // Handle ASCII armor case specially
        use age::armor::Format;
        let mut armored_writer = ArmoredWriter::wrap_output(&mut output_buffer, Format::AsciiArmor)
            .map_err(|e| Error::Other(format!("Failed to create armored writer: {}", e)))?;
        
        // Encrypt and write to armored writer
        let mut encrypted_writer = encryptor.wrap_output(&mut armored_writer)
            .map_err(|e| Error::Other(format!("Failed to wrap output for encryption: {}", e)))?;
        
        encrypted_writer.write_all(input_string.as_bytes())
            .map_err(|e| Error::Other(format!("Failed to write encrypted data: {}", e)))?;
        
        encrypted_writer.finish()
            .map_err(|e| Error::Other(format!("Failed to finalize encryption: {}", e)))?;
        
        // Must finish the armored writer to get complete output
        armored_writer.finish()
            .map_err(|e| Error::Other(format!("Failed to finalize armored writer: {}", e)))?;
        
        // Return ASCII armor as string
        Ok(String::from_utf8(output_buffer)
            .map_err(|e| Error::Other(format!("Failed to convert armored output to string: {}", e)))?)
    } else {
        // Handle binary case - encrypt directly to buffer
        let mut encrypted_writer = encryptor.wrap_output(&mut output_buffer)
            .map_err(|e| Error::Other(format!("Failed to wrap output for encryption: {}", e)))?;
        
        encrypted_writer.write_all(input_string.as_bytes())
            .map_err(|e| Error::Other(format!("Failed to write encrypted data: {}", e)))?;
        
        encrypted_writer.finish()
            .map_err(|e| Error::Other(format!("Failed to finalize encryption: {}", e)))?;
        
        // Return binary as base64
        use base64::{Engine as _, engine::general_purpose};
        Ok(general_purpose::STANDARD.encode(&output_buffer))
    }
}

/// Encrypt a string using age with a passphrase
/// 
/// This function encrypts a string using a passphrase-based encryption.
/// Returns the encrypted content as a base64-encoded string.
/// @keywords internal
/// @noRd
#[extendr]
fn age_encrypt_string_with_passphrase(input_string: &str, passphrase: &str) -> Result<String> {
    use age::secrecy::SecretString;
    use std::io::Write;
    
    // Create scrypt encryptor (reuse from age_encrypt_passphrase)
    let secret_pass = SecretString::from(passphrase.to_owned());
    let encryptor = age::Encryptor::with_user_passphrase(secret_pass);
    
    // Use in-memory buffer instead of file
    let mut output_buffer = Vec::new();
    
    // Encrypt and write (similar to age_encrypt_passphrase)
    let mut encrypted_writer = encryptor.wrap_output(&mut output_buffer)
        .map_err(|e| Error::Other(format!("Failed to wrap output for encryption: {}", e)))?;
    
    encrypted_writer.write_all(input_string.as_bytes())
        .map_err(|e| Error::Other(format!("Failed to write encrypted data: {}", e)))?;
    
    encrypted_writer.finish()
        .map_err(|e| Error::Other(format!("Failed to finalize encryption: {}", e)))?;
    
    // Return as base64-encoded string
    use base64::{Engine as _, engine::general_purpose};
    Ok(general_purpose::STANDARD.encode(&output_buffer))
}

/// Decrypt an encrypted string using a passphrase
/// 
/// This function decrypts a base64-encoded or ASCII-armored encrypted string using a passphrase.
/// Returns the decrypted content as a string.
/// @keywords internal
/// @noRd
#[extendr]
fn age_decrypt_string_with_passphrase(encrypted_string: &str, passphrase: &str) -> Result<String> {
    use age::secrecy::SecretString;
    use std::iter;
    
    // Handle both ASCII armor and base64-encoded binary
    let encrypted_bytes = if encrypted_string.starts_with("-----BEGIN AGE ENCRYPTED FILE-----") {
        // For ASCII armor, we need to include the full string with newlines properly
        encrypted_string.as_bytes().to_vec()
    } else {
        // For base64-encoded binary, decode first
        use base64::{Engine as _, engine::general_purpose};
        general_purpose::STANDARD.decode(encrypted_string)
            .map_err(|e| Error::Other(format!("Failed to decode base64: {}", e)))?
    };
    
    // Create scrypt identity (reuse from age_decrypt_with_passphrase)
    let secret_pass = SecretString::from(passphrase.to_owned());
    let identity = age::scrypt::Identity::new(secret_pass);
    
    
    // Decrypt using existing decrypt_content function
    let decrypted_bytes = decrypt_content(&encrypted_bytes, iter::once(&identity as _))?;
    
    // Convert to string
    String::from_utf8(decrypted_bytes)
        .map_err(|e| Error::Other(format!("Failed to convert decrypted content to UTF-8: {}", e)))
}

/// Decrypt an encrypted string using a private key
/// 
/// This function decrypts a base64-encoded or ASCII-armored encrypted string using a private key.
/// Returns the decrypted content as a string.
/// @keywords internal
/// @noRd
#[extendr]
fn age_decrypt_string_with_key(encrypted_string: &str, private_key_path: &str) -> Result<String> {
    // Handle both ASCII armor and base64-encoded binary
    let encrypted_bytes = if encrypted_string.starts_with("-----BEGIN AGE ENCRYPTED FILE-----") {
        // For ASCII armor, we need to include the full string with newlines properly
        encrypted_string.as_bytes().to_vec()
    } else {
        // For base64-encoded binary, decode first
        use base64::{Engine as _, engine::general_purpose};
        general_purpose::STANDARD.decode(encrypted_string)
            .map_err(|e| Error::Other(format!("Failed to decode base64: {}", e)))?
    };
    
    // Read private key file (reuse from age_decrypt_with_key)
    let key_content = std::fs::read_to_string(private_key_path)
        .map_err(|_| Error::Other("Failed to read private key file".to_string()))?;
    
    // Parse identities using existing function
    let identities = parse_identities_from_key_file(&key_content)?;
    
    
    // Decrypt using existing decrypt_content function
    let decrypted_bytes = decrypt_content(&encrypted_bytes, identities.iter().map(|i| i.as_ref()))?;
    
    // Convert to string
    String::from_utf8(decrypted_bytes)
        .map_err(|e| Error::Other(format!("Failed to convert decrypted content to UTF-8: {}", e)))
}

// Register the Rust functions with R's extendr system
// This macro generates the necessary C bindings for R to call our Rust functions
extendr_module! {
    mod lockbox;
    fn age_decrypt_with_passphrase;
    fn age_decrypt_with_key;
    fn age_generate_key;
    fn age_extract_public_key;
    fn age_encrypt_key;
    fn age_encrypt_passphrase;
    fn age_encrypt_string_with_key;
    fn age_encrypt_string_with_passphrase;
    fn age_decrypt_string_with_passphrase;
    fn age_decrypt_string_with_key;
}

// Bridge between Rust and R for age encryption/decryption functionality
use extendr_api::prelude::*;
use std::io::Read;
use std::str::FromStr;
use age::secrecy::ExposeSecret;

/// Decrypt file content using identities and return as string
/// 
/// This helper function handles both ASCII-armored and binary age files,
/// decrypts them, and returns the content as a string.
fn decrypt_content<'a, I>(file_content: &[u8], identities: I) -> Result<String>
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

    let mut decrypted_content = String::new();
    decrypted_reader.read_to_string(&mut decrypted_content)
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
/// It reads the entire file into memory, detects the format, and returns the decrypted content as a string.
/// @keywords internal
/// @noRd
#[extendr]
fn age_decrypt_passphrase(encrypted_file_path: &str, passphrase: &str) -> Result<String> {
    use age::secrecy::SecretString;
    use std::iter;

    // Read the entire encrypted file into memory
    let file_content = std::fs::read(encrypted_file_path)
        .map_err(|e| Error::Other(format!("Failed to read file: {}", e)))?;

    // Create scrypt identity from passphrase for secure decryption
    let secret_pass = SecretString::from(passphrase.to_owned());
    let identity = age::scrypt::Identity::new(secret_pass);
    
    // Decrypt and return content using the passphrase identity
    decrypt_content(&file_content, iter::once(&identity as _))
}

/// Decrypt an age-encrypted file using a private key
/// 
/// This function handles both ASCII-armored and binary age files encrypted with public keys.
/// It reads the private key file, parses all identities, and returns the decrypted content as a string.
/// @keywords internal
/// @noRd
#[extendr]
fn age_decrypt_key(encrypted_file_path: &str, private_key_path: &str) -> Result<String> {
    // Read the encrypted file and private key file
    let file_content = std::fs::read(encrypted_file_path)
        .map_err(|e| Error::Other(format!("Failed to read file: {}", e)))?;

    let key_content = std::fs::read_to_string(private_key_path)
        .map_err(|e| Error::Other(format!("Failed to read key file: {}", e)))?;

    // Parse all age identities from the key file
    let identities = parse_identities_from_key_file(&key_content)?;
    
    // Decrypt and return content using all available identities
    decrypt_content(&file_content, identities.iter().map(|i| i.as_ref()))
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
        .map_err(|e| Error::Other(format!("Failed to create key file: {}", e)))?;
    
    file.write_all(private_key_line.as_bytes())
        .map_err(|e| Error::Other(format!("Failed to write key file: {}", e)))?;
    
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
        .map_err(|e| Error::Other(format!("Failed to read key file: {}", e)))?;

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

// Register the Rust functions with R's extendr system
// This macro generates the necessary C bindings for R to call our Rust functions
extendr_module! {
    mod lockbox;
    fn age_decrypt_passphrase;
    fn age_decrypt_key;
    fn age_generate_key;
    fn age_extract_public_key;
}

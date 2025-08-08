// Bridge between Rust and R for age encryption/decryption functionality
use extendr_api::prelude::*;
use std::io::Read;
use std::str::FromStr;

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

// Register the Rust functions with R's extendr system
// This macro generates the necessary C bindings for R to call our Rust functions
extendr_module! {
    mod lockbox;
    fn age_decrypt_passphrase;
    fn age_decrypt_key;
}

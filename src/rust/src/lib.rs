// ============================================================================
// IMPORTS AND DEPENDENCIES
// ============================================================================

// Import extendr-api prelude - provides the bridge between Rust and R
// The prelude includes commonly used types like Result, Error, etc.
use extendr_api::prelude::*;

// Import std::io::Read trait - this is Rust's standard trait for reading data
// A trait in Rust is similar to an interface in other languages
use std::io::Read;

// Import FromStr trait - allows parsing strings into other types
// This is used to parse age private keys from string format
use std::str::FromStr;

// ============================================================================
// MAIN FUNCTION DEFINITION
// ============================================================================

/// Decrypt an age-encrypted file and return the content as a string
/// 
/// This function reads an age-encrypted file, decrypts it using the provided
/// private key or passphrase, and returns the decrypted content as a string 
/// without writing it to disk.
/// 
/// @param encrypted_file_path Path to the age-encrypted file
/// @param private_key_path Path to the age private key file (optional if using passphrase)
/// @param passphrase Passphrase for decryption (optional if using private key)
/// @return Decrypted content as string
/// @keywords internal
/// @noRd
#[extendr]  // This attribute tells rextendr to create R bindings for this function
fn age_decrypt(
    // Function parameters with Rust type annotations:
    encrypted_file_path: &str,           // &str = borrowed string slice (read-only reference)
    private_key_path: Option<&str>,      // Option<T> = can be Some(value) or None (like nullable)
    passphrase: Option<&str>             // Same as above - optional string parameter
) -> Result<String> {                    // Result<T> = can be Ok(value) or Err(error)
    
    // ========================================================================
    // LOCAL IMPORTS
    // ========================================================================
    // These are imported locally to avoid cluttering the global namespace
    // Similar to importing inside a function in Python
    
    use age::armor::ArmoredReader;       // Handles ASCII-armored age files
    use age::{Decryptor, Identity};      // Core age decryption types
    use std::io::Cursor;                 // Creates a Read-able cursor from byte data
    
    // ========================================================================
    // INPUT VALIDATION
    // ========================================================================
    
    // Check that exactly one authentication method is provided
    // .is_none() and .is_some() are methods on Option<T>
    if private_key_path.is_none() && passphrase.is_none() {
        // Early return with error - using ? operator for error propagation
        // Error::Other() creates an error variant, .to_string() converts &str to String
        return Err(Error::Other("Either private_key_path or passphrase must be provided".to_string()));
    }
    
    if private_key_path.is_some() && passphrase.is_some() {
        return Err(Error::Other("Cannot specify both private_key_path and passphrase".to_string()));
    }

    // ========================================================================
    // FILE READING
    // ========================================================================
    
    // Read entire file into memory as bytes (Vec<u8>)
    // std::fs::read() returns Result<Vec<u8>, std::io::Error>
    let file_content = std::fs::read(encrypted_file_path)
        // .map_err() transforms the error type - if reading fails, convert io::Error to our Error type
        .map_err(|e| Error::Other(format!("Failed to read encrypted file: {}", e)))?;
        // The ? operator at the end means: if this is Err, return early with that error

    // ========================================================================
    // FILE FORMAT DETECTION AND DECRYPTION SETUP
    // ========================================================================
    
    // Declare a variable to hold our decrypted reader
    // Box<dyn Read> = heap-allocated trait object that implements Read
    // This allows us to store different types that all implement Read
    let decrypted_reader: Box<dyn Read> = 
        
        // Check if file starts with ASCII armor header
        if file_content.starts_with(b"-----BEGIN AGE ENCRYPTED FILE-----") {
            // b"string" creates a byte string literal
            
            // ================================================================
            // ARMORED FILE HANDLING
            // ================================================================
            
            // Create a cursor (in-memory reader) from our byte data
            // &file_content borrows a reference to the vector
            let cursor = Cursor::new(&file_content);
            
            // Wrap cursor in armor reader to handle ASCII format
            let armored_reader = ArmoredReader::new(cursor);
            
            // Create decryptor from the armored reader
            // This returns Result<Decryptor, age::Error>
            let decryptor = Decryptor::new(armored_reader)
                .map_err(|e| Error::Other(format!("Failed to create armored decryptor: {}", e)))?;
            
            // Match on the decryptor type - Rust's pattern matching (like switch/case)
            // Decryptor is an enum with two variants: Recipients or Passphrase
            match decryptor {
                // If it's Recipients-encrypted (key-based)
                Decryptor::Recipients(d) => {
                    // Pattern match on Option using if let
                    // if let Some(value) = option means "if option contains a value, bind it to 'value'"
                    if let Some(key_path) = private_key_path {
                        
                        // ============================================
                        // KEY-BASED DECRYPTION FOR ARMORED FILE
                        // ============================================
                        
                        // Read the private key file as a UTF-8 string
                        let key_content = std::fs::read_to_string(key_path)
                            .map_err(|e| Error::Other(format!("Failed to read private key file: {}", e)))?;
                        
                        // Create a vector to store parsed identities
                        // Vec<T> = growable array, like ArrayList in Java
                        // Box<dyn Identity> = heap-allocated trait object
                        let mut identities: Vec<Box<dyn Identity>> = Vec::new();
                        
                        // Iterate over each line in the key file
                        // .lines() returns an iterator over lines
                        for line in key_content.lines() {
                            // Check if line starts with age secret key prefix
                            if line.starts_with("AGE-SECRET-KEY-") {
                                // Parse the identity from the line
                                // FromStr::from_str() is a trait method for parsing
                                let identity = age::x25519::Identity::from_str(line)
                                    .map_err(|e| Error::Other(format!("Failed to parse identity: {}", e)))?;
                                
                                // Box::new() allocates on heap, 'as Box<dyn Identity>' casts to trait object
                                identities.push(Box::new(identity) as Box<dyn Identity>);
                            }
                        }
                        
                        // Check that we found at least one identity
                        if identities.is_empty() {
                            return Err(Error::Other("No valid age identities found in private key file".to_string()));
                        }
                        
                        // Decrypt using the identities
                        // .iter() creates iterator, .map(|i| i.as_ref()) converts Box<T> to &T
                        // Box::new() wraps the result in a heap-allocated trait object
                        Box::new(d.decrypt(identities.iter().map(|i| i.as_ref()))
                            .map_err(|e| Error::Other(format!("Failed to decrypt armored file with key: {}", e)))?)
                            
                    } else {
                        // We have a Recipients file but no key provided
                        return Err(Error::Other("Recipients-encrypted file requires a private key, not a passphrase".to_string()));
                    }
                }
                
                // If it's Passphrase-encrypted
                Decryptor::Passphrase(d) => {
                    if let Some(pass) = passphrase {
                        
                        // ============================================
                        // PASSPHRASE-BASED DECRYPTION FOR ARMORED FILE
                        // ============================================
                        
                        // Wrap passphrase in Secret type for security
                        // .to_string() converts &str to owned String
                        let secret_pass = age::secrecy::Secret::new(pass.to_string());
                        
                        // Decrypt with passphrase (None = no work factor override)
                        Box::new(d.decrypt(&secret_pass, None)
                            .map_err(|e| Error::Other(format!("Failed to decrypt armored file with passphrase: {}", e)))?)
                            
                    } else {
                        // We have a Passphrase file but no passphrase provided
                        return Err(Error::Other("Passphrase-encrypted file requires a passphrase, not a private key".to_string()));
                    }
                }
            }
            
        } else {
            // ================================================================
            // BINARY FILE HANDLING
            // ================================================================
            // Same logic as armored, but for binary age files
            
            let cursor = Cursor::new(&file_content);
            let decryptor = Decryptor::new(cursor)
                .map_err(|e| Error::Other(format!("Failed to create binary decryptor: {}", e)))?;
            
            match decryptor {
                Decryptor::Recipients(d) => {
                    if let Some(key_path) = private_key_path {
                        // Key-based decryption (same logic as armored)
                        let key_content = std::fs::read_to_string(key_path)
                            .map_err(|e| Error::Other(format!("Failed to read private key file: {}", e)))?;
                        
                        let mut identities: Vec<Box<dyn Identity>> = Vec::new();
                        for line in key_content.lines() {
                            if line.starts_with("AGE-SECRET-KEY-") {
                                let identity = age::x25519::Identity::from_str(line)
                                    .map_err(|e| Error::Other(format!("Failed to parse identity: {}", e)))?;
                                identities.push(Box::new(identity) as Box<dyn Identity>);
                            }
                        }
                        
                        if identities.is_empty() {
                            return Err(Error::Other("No valid age identities found in private key file".to_string()));
                        }
                        
                        Box::new(d.decrypt(identities.iter().map(|i| i.as_ref()))
                            .map_err(|e| Error::Other(format!("Failed to decrypt binary file with key: {}", e)))?)
                    } else {
                        return Err(Error::Other("Recipients-encrypted file requires a private key, not a passphrase".to_string()));
                    }
                }
                Decryptor::Passphrase(d) => {
                    if let Some(pass) = passphrase {
                        // Passphrase-based decryption (same logic as armored)
                        let secret_pass = age::secrecy::Secret::new(pass.to_string());
                        Box::new(d.decrypt(&secret_pass, None)
                            .map_err(|e| Error::Other(format!("Failed to decrypt binary file with passphrase: {}", e)))?)
                    } else {
                        return Err(Error::Other("Passphrase-encrypted file requires a passphrase, not a private key".to_string()));
                    }
                }
            }
        }; // End of the big if-else expression that creates decrypted_reader

    // ========================================================================
    // READ DECRYPTED CONTENT
    // ========================================================================
    
    // Create a mutable String to store the result
    // mut keyword makes a variable mutable (can be changed)
    let mut decrypted_content = String::new();
    
    // Make the reader mutable so we can read from it
    let mut reader = decrypted_reader;
    
    // Read all content from the decrypted stream into our string
    // read_to_string() is a method from the Read trait
    reader.read_to_string(&mut decrypted_content)
        .map_err(|e| Error::Other(format!("Failed to read decrypted content: {}", e)))?;

    // Return the decrypted content wrapped in Ok()
    // This is the success case of Result<T, E>
    Ok(decrypted_content)
}

// ============================================================================
// REXTENDR MODULE REGISTRATION
// ============================================================================

// This macro generates the necessary C code to register our Rust functions with R
// It creates the bridge that allows R to call our Rust functions
// The macro creates C functions that R's .Call() interface can invoke
extendr_module! {
    mod lockbox;                    // The name of our module (should match the crate name)
    fn age_decrypt;       // List all functions we want to export to R
}

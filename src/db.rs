use std::{
    path::Path,
    fs::File,
    io::{
        BufReader,
        Write
    },
    error::Error,
    collections::HashMap
};

use aes_gcm::{
    aead::{
        Aead,
        KeyInit,
        generic_array::GenericArray
    },
    Aes256Gcm,
    Nonce
};

use serde::{
    Serialize,
    Deserialize
};

use sha2::{
    Sha256,
    Digest,
    digest::typenum::{UInt, UTerm, B0, B1}
};

use colored::*;

macro_rules! scan {
    () => {{
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).unwrap();
        String::from(line.trim_end())
    }};

    ($var:expr) => {{
        print!("{}: ", $var);
        match std::io::stdout().flush() {
            Ok(_) => {},
            Err(err) => panic!("{}", err)
        };
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).unwrap();
        String::from(line.trim_end())
    }}
}

fn get_key() -> GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>, B0>> {
    let key = rpassword::prompt_password("Your key: ").unwrap();
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());

    let cipher_key = hasher.finalize();

    return cipher_key;
}

#[derive(Serialize, Deserialize)]
pub struct Database(HashMap<String, String>);

impl Database {
    fn read() -> Result<Database, Box<dyn Error>> {
        let path = Path::new(env!("APPDATA")).join(".pass_manager.config");

        let file = match File::open(path.as_path()) {
            Ok(f) => f,
            Err(_) => panic!("Try running pass init")
        };
        let reader = BufReader::new(file);
        let db: Database = serde_json::from_reader(reader)?;

        Ok(db)
    }

    fn write(self) -> Result<(), Box<dyn Error>> {
        let json = serde_json::to_string_pretty(&self.0)?;

        let path = Path::new(env!("APPDATA")).join(".pass_manager.config");
        let mut file = File::create(&path)?;
        file.write_all(json.as_bytes())?;

        Ok(())
    }

    pub fn init() -> Result<(), Box<dyn Error>> {
        let empty: HashMap<String, String> = HashMap::new();
        let json = serde_json::to_string_pretty(&empty)?;

        let path = Path::new(env!("APPDATA")).join(".pass_manager.config");
        
        if path.exists() {
            return Err(format!("The passwords db already exists. Try {}", "pass reset".black().on_white()).into());
        }
        let mut file = File::create(path.as_path())?;

        file.write_all(json.as_bytes())?;

        Ok(())
    }

    pub fn add() -> Result<(), Box<dyn Error>> {
        let mut database = Database::read()?;

        let label = scan!("Enter label");
        let password = scan!("Enter password");
        let cipher = Aes256Gcm::new(GenericArray::from_slice(get_key().as_slice()));
        let nonce = Nonce::from_slice(b"unique nonce");

        let ciphertext = match cipher.encrypt(nonce, password.as_bytes().as_ref()) {
            Ok(v) => v,
            Err(e) => return Err(format!("Error ocuured while encryption: {}", e).into()),
        };

        database.0.insert(label, hex::encode(ciphertext));
        database.write()
    }

    pub fn remove() -> Result<(), Box<dyn Error>> {
        let label = scan!("Enter label");
        
        let mut database = Database::read()?;
        match database.0.remove(&label) {
            Some(_) => {},
            None => return Err(format!("No entry found with label \"{}\" ", label).into())
        };

        database.write()
    }

    pub fn modify() -> Result<(), Box<dyn Error>> {
        let label = scan!("Enter label");
        
        let mut database = Database::read()?;
        match database.0.remove(&label) {
            Some(_) => {},
            None => return Err(format!("No entry found with label \"{}\" ", label).into())
        };

        let password = scan!("Enter password");
        let cipher = Aes256Gcm::new(GenericArray::from_slice(get_key().as_slice()));
        let nonce = Nonce::from_slice(b"unique nonce");

        let ciphertext = match cipher.encrypt(nonce, password.as_bytes().as_ref()) {
            Ok(v) => v,
            Err(e) => return Err(format!("Error ocuured while encryption: {}", e).into()),
        };

        database.0.insert(label, hex::encode(ciphertext));
        database.write()
    }

    pub fn view() -> Result<(), Box<dyn Error>> {
        let database = Database::read()?;
        let label = scan!("Enter label");

        let password = match database.0.get(&label) {
            Some(n) => n,
            None => return Err(format!("No passwords found with label {}", label).into())
        };

        let cipher = Aes256Gcm::new(GenericArray::from_slice(get_key().as_slice()));
        let nonce = Nonce::from_slice(b"unique nonce");

        let plaintext = match cipher.decrypt(nonce, hex::decode(password)?.as_slice().as_ref()) {
            Ok(v) => v,
            Err(e) => return Err(format!("Error ocuured while decryption: {}", e).into()),
        };

        println!("{}", String::from_utf8(plaintext)?);
        Ok(())
    }

    pub fn list() -> Result<(), Box<dyn Error>> {
        let database = Database::read()?;
        let max = match database.0.keys().map(String::len).max() {
            Some(n) => n,
            None => return Err("No passwords found".into())
        };

        let cipher = Aes256Gcm::new(GenericArray::from_slice(get_key().as_slice()));
        let nonce = Nonce::from_slice(b"unique nonce");

        println!("{:^max$} {:^max$}", "Labels", "Passwords", max = max);
        println!();
        for (k, v) in database.0 {
            let plaintext = match cipher.decrypt(nonce, hex::decode(v)?.as_slice().as_ref()) {
                Ok(v) => v,
                Err(e) => return Err(format!("Error ocuured while decryption: {}", e).into()),
            };
            println!("{:width$} {:width$}", k, String::from_utf8(plaintext)?, width = max);
        }
        Ok(())
    }

    pub fn reset() -> Result<(), Box<dyn Error>> {
        let conformation = scan!("Are you sure you want to reset passwords? (y/n)");
        if conformation == "y" {
            let empty: HashMap<String, String> = HashMap::new();
            let json = serde_json::to_string_pretty(&empty)?;
    
            let path = Path::new(env!("APPDATA")).join(".pass_manager.config");
            let mut file = File::create(path.as_path())?;
    
            file.write_all(json.as_bytes())?;
            Ok(())
        } else {
            Ok(())
        }
    }
}
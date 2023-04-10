use colored::*;
use std::{
    path::{Path, PathBuf},
    fs::{File, OpenOptions},
    io::{Write, Read},
    error::Error,
    collections::{BTreeMap, btree_map::Entry::{Occupied, Vacant}},
};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm,
    Nonce
};

use rand::Rng;
use sha2::{Sha256, Digest};

use crate::table::Table;

#[macro_export]
macro_rules! scan {
    ($var:expr) => {{
        print!("{}: ", $var);
        match std::io::stdout().flush() {
            Ok(_) => {},
            Err(err) => panic!("{}", err)
        };
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).unwrap();
        String::from(line.trim_end())
    }};

    ($var:tt) => {{
        print!("{} ", stringify!($var));
        match std::io::stdout().flush() {
            Ok(_) => {},
            Err(err) => panic!("{}", err)
        };
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).unwrap();
        String::from(line.trim_end())
    }}
}

pub struct PassManager {
    db: BTreeMap<String, ([u8; 12], Vec<u8>)>,
    path: PathBuf,
    cipher: Aes256Gcm
}

impl PassManager {
    pub fn new<P: AsRef<Path> + Clone>(path: P) -> Result<Self, Box<dyn Error>> {
        let bin_path = path.as_ref().with_extension("bin");
        let sha_path = path.as_ref().with_extension("sha");

        if !bin_path.exists() {
            File::create(bin_path.clone())?;
            let key = rpassword::prompt_password("Enter a key: ").unwrap();
            let salt: [u8; 16] = rand::random();

            let mut salted = salt.to_vec();
            salted.extend_from_slice(key.as_bytes());

            let cipher_key = Sha256::digest(&salted);

            let mut f = File::create(sha_path)?;
            f.write_all(&salt)?;
            f.write_all(&cipher_key)?;

            return Ok(Self {
                db: BTreeMap::new(),
                path: bin_path,
                cipher: Aes256Gcm::new(&cipher_key)
            });
        }

        let key = rpassword::prompt_password("Your key: ").unwrap();

        let mut sha_file = File::open(sha_path)?;

        let mut salt = [0; 16];

        sha_file.read_exact(&mut salt)?;

        let mut salted = salt.to_vec();
        salted.extend_from_slice(key.as_bytes());

        let cipher_key = Sha256::digest(&salted);

        let mut hash: [u8; 32] = [0; 32];
        sha_file.read_exact(&mut hash)?;

        if cipher_key.as_slice() != hash {
            return Err("Incorrect password".into());
        }

        let cipher = Aes256Gcm::new(&cipher_key);

        let mut file = File::open(bin_path.clone())?;

        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;

        let mut aligned_buf = rkyv::AlignedVec::new();
        aligned_buf.extend_from_slice(&buf);

        let db = rkyv::from_bytes(&aligned_buf)?;

        Ok(Self { db, cipher, path: bin_path })
    }

    pub fn exit(self) {
        let data = rkyv::to_bytes::<_, 1024>(&self.db).unwrap();

        let mut file = OpenOptions::new().write(true).open(self.path).unwrap();
        file.write_all(&data).unwrap();
    }

    pub fn help(&self) -> Result<(), Box<dyn Error>> {
        println!("{}",
    "Commands:
        help:   Print the help message
        add:    Add a new password
        remove: Remove a password
        modify: Modify an existing password
        view:   View a password
        list:   List all passwords
        reset:  Reset all passwords
        gen:    Generate a random password and save it.".green());
        Ok(())
    }

    pub fn add(&mut self, label: String, password: String) -> Result<(), Box<dyn Error>> {
        let nonce_slice: [u8; 12] = rand::random();

        let nonce = Nonce::from_slice(&nonce_slice);

        let ciphertext = match self.cipher.encrypt(nonce, password.as_bytes().as_ref()) {
            Ok(v) => v,
            Err(e) => return Err(format!("Error ocuured while encryption: {}", e).into()),
        };

        match self.db.entry(label.clone()) {
            Vacant(entry) => {
                entry.insert((nonce_slice, ciphertext));
            },
            Occupied(mut entry) => {
                let choice = scan!(format!("A password exists for \"{label}\". Do you want to overwrite? (y/n)"));
                if choice == "y" {
                    entry.insert((nonce_slice, ciphertext));
                }
            }
        };

        Ok(())
    }

    pub fn remove(&mut self, label: String) -> Result<(), Box<dyn Error>> {
        match self.db.remove(&label) {
            Some(_) => {},
            None => return Err(format!("No entry found with label \"{}\" ", label).into())
        };

        Ok(())
    }

    pub fn modify(&mut self, label: String, password: String) -> Result<(), Box<dyn Error>> {
        match self.db.remove(&label) {
            Some(_) => {},
            None => return Err(format!("No entry found with label \"{}\" ", label).into())
        };

        let nonce_slice: [u8; 12] = rand::random();
        let nonce = Nonce::from_slice(&nonce_slice);

        let ciphertext = match self.cipher.encrypt(nonce, password.as_bytes()) {
            Ok(v) => v,
            Err(e) => return Err(format!("Error ocuured while encryption: {}", e).into()),
        };

        self.db.insert(label, (nonce_slice, ciphertext));

        Ok(())
    }

    pub fn view(&self, label: String) -> Result<(), Box<dyn Error>> {
        let (nonce, password) = match self.db.get(&label) {
            Some(n) => n,
            None => return Err(format!("No passwords found with label {}", label).into())
        };

        let nonce = Nonce::from_slice(nonce);

        let plaintext = match self.cipher.decrypt(nonce, password.as_slice()) {
            Ok(v) => v,
            Err(e) => return Err(format!("Error ocuured while decryption: {}", e).into()),
        };

        println!("{}", String::from_utf8(plaintext)?);

        Ok(())
    }

    pub fn list(&self) -> Result<(), Box<dyn Error>> {
        if self.db.is_empty() {
            return Err("No passwords found".into());
        }
        let mut t = Table::new(vec!["Labels".into(), "Passwords".into()]);

        for (label, (nonce, password)) in self.db.clone() {
            let nonce = Nonce::from_slice(&nonce);
            let plaintext = match self.cipher.decrypt(nonce, password.as_slice()) {
                Ok(v) => v,
                Err(e) => return Err(format!("Error ocuured while decryption: {}", e).into()),
            };

            t.insert(vec![label, String::from_utf8(plaintext)?]);
        }

        t.display()
    }

    pub fn reset(&mut self) -> Result<(), Box<dyn Error>> {
        let conf = scan!("Are you sure you want to reset passwords? (y/n)");
        if conf == "y" {
            self.db = BTreeMap::new();
        }

        Ok(())
    }

    pub fn gen(&mut self, label: String, len: usize) -> Result<(), Box<dyn Error>> {
        let mut rng = rand::thread_rng();
        let range = if scan!("Do you want special chars? (y/n)") == "y" { 94 } else { 62 };
        let password_charset = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

        let mut password = String::with_capacity(len);
        for _ in 0..len {
            let pos = rng.gen_range(0..range);
            password.push(char::from_u32(password_charset[pos] as u32).unwrap())
        }

        println!("{password}");

        self.add(label, password)
    }
}

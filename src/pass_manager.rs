use colored::*;
use rkyv::AlignedVec;
use std::{
    path::{Path, PathBuf},
    fs::{File, OpenOptions},
    io::{Write, Read, Seek, SeekFrom},
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
use sha3::Sha3_256;

use crate::table::Table;

macro_rules! scan {
    ($var:expr, $ident:tt) => {
        print!("{}", $var);
        std::io::stdout().flush()?;
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).unwrap();
        let $ident = String::from(line.trim_end());
    };
}

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[archive(check_bytes)]
struct Users(BTreeMap<String, ([u8; 16], [u8; 32])>);

impl Users {
    fn new<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn Error>> {
        let mut f = File::open(path.as_ref().with_extension("users"))?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf)?;

        let mut aligned_buf = AlignedVec::new();
        aligned_buf.extend_from_slice(&buf);

        let users = rkyv::from_bytes::<Users>(&aligned_buf)?;

        Ok(users)
    }

    fn check(&self, username: String, password: String) -> Result<Vec<u8>, Box<dyn Error>> {
        let &(salt, hash) = match self.0.get(&username) {
            Some(val) => val,
            None => return Err(format!("No user \"{}\" found!", username).into())
        };

        let password_bytes = [&salt, password.as_bytes()].concat();

        let digest = Sha3_256::digest(password_bytes.clone());

        if digest.ne(&hash.into()) {
            return Err("Incorrect password!".into());
        }

        Ok(Sha256::digest(password_bytes).to_vec())
    }

    fn create<P: AsRef<Path>>(path: P, username: String, salt: [u8; 16], hash: [u8; 32]) -> Result<(), Box<dyn Error>> {
        let mut users = match std::fs::read(path.as_ref().with_extension("users")) {
            Ok(buf) => {let mut aligned_buf = AlignedVec::new();
                aligned_buf.extend_from_slice(&buf);

                let users = rkyv::from_bytes::<Users>(&aligned_buf)?;
                users
            }

            Err(_) => Users(BTreeMap::new())
        };

        users.0.insert(username.clone(), (salt, hash));
        File::create(path.as_ref().with_extension(username))?;

        std::fs::write(path.as_ref().with_extension("users"), rkyv::to_bytes::<_, 1024>(&users)?)?;

        Ok(())
    }
}

pub struct PassManager {
    passwords: BTreeMap<String, ([u8; 12], Vec<u8>)>,
    path: PathBuf,
    cipher: Aes256Gcm
}

impl PassManager {
    pub fn new<P: AsRef<Path> + Clone>(path: P) -> Result<Self, Box<dyn Error>> {
        scan!("Enter your username: ", username);

        let bin_path = path.as_ref().with_extension(username.clone());

        if !bin_path.exists() {
            File::create(bin_path.clone())?;
            let key = rpassword::prompt_password("Enter a key: ").unwrap();
            let salt: [u8; 16] = rand::random();

            let mut salted = salt.to_vec();
            salted.extend_from_slice(key.as_bytes());

            let cipher_key = Sha256::digest(&salted);

            Users::create(path, username, salt, Sha3_256::digest(&salted).into())?;

            return Ok(Self {
                passwords: BTreeMap::new(),
                path: bin_path,
                cipher: Aes256Gcm::new(&cipher_key)
            });
        }

        let users = Users::new(path)?;

        let key = rpassword::prompt_password("Your key: ").unwrap();
        let cipher_key = users.check(username, key)?;

        let cipher = Aes256Gcm::new(cipher_key.as_slice().into());

        let mut buf = Vec::new();

        let mut file = File::open(bin_path.clone())?;
        file.read_to_end(&mut buf)?;

        let mut aligned_buf = rkyv::AlignedVec::new();
        aligned_buf.extend_from_slice(&buf);

        let passwords = rkyv::from_bytes(&aligned_buf)?;

        Ok(Self { passwords, cipher, path: bin_path })
    }

    pub fn exit(self) {
        let data = rkyv::to_bytes::<_, 1024>(&self.passwords).unwrap();

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
        copy:   Copy a password
        gen:    Generate a random password and save it
        list:   List all passwords of the user
        reset:  Reset all passwords of the user
        logout: Logout from current user
        create: Create a new user
        change: Change the current user's password.".green());
        Ok(())
    }

    pub fn add(&mut self, label: String, password: String) -> Result<(), Box<dyn Error>> {
        let nonce_slice: [u8; 12] = rand::random();

        let nonce = Nonce::from_slice(&nonce_slice);

        let ciphertext = match self.cipher.encrypt(nonce, password.as_bytes().as_ref()) {
            Ok(v) => v,
            Err(e) => return Err(format!("Error ocuured while encryption: {}", e).into()),
        };

        match self.passwords.entry(label.clone()) {
            Vacant(entry) => {
                entry.insert((nonce_slice, ciphertext));
            },
            Occupied(mut entry) => {
                scan!(format!("A password exists for \"{label}\". Do you want to overwrite? (y/n)"), choice);
                if choice == "y" {
                    entry.insert((nonce_slice, ciphertext));
                }
            }
        };

        Ok(())
    }

    pub fn remove(&mut self, label: String) -> Result<(), Box<dyn Error>> {
        match self.passwords.remove(&label) {
            Some(_) => {},
            None => return Err(format!("No entry found with label \"{}\" ", label).into())
        };

        Ok(())
    }

    pub fn modify(&mut self, label: String, password: String) -> Result<(), Box<dyn Error>> {
        match self.passwords.remove(&label) {
            Some(_) => {},
            None => return Err(format!("No entry found with label \"{}\" ", label).into())
        };

        let nonce_slice: [u8; 12] = rand::random();
        let nonce = Nonce::from_slice(&nonce_slice);

        let ciphertext = match self.cipher.encrypt(nonce, password.as_bytes()) {
            Ok(v) => v,
            Err(e) => return Err(format!("Error ocuured while encryption: {}", e).into()),
        };

        self.passwords.insert(label, (nonce_slice, ciphertext));

        Ok(())
    }

    pub fn copy(&self, label: String) -> Result<(), Box<dyn Error>> {
        let (nonce, password) = match self.passwords.get(&label) {
            Some(n) => n,
            None => return Err(format!("No passwords found with label \"{}\"", label).into())
        };

        let nonce = Nonce::from_slice(nonce);

        let plaintext = match self.cipher.decrypt(nonce, password.as_slice()) {
            Ok(v) => v,
            Err(e) => return Err(format!("Error ocuured while decryption: {}", e).into()),
        };

        match clipboard_win::set_clipboard_string(String::from_utf8(plaintext)?.as_str()) {
            Ok(()) => Ok(()),
            Err(err) => Err(format!("Unable to set password to clipboard. Error: {}", err.message()).into())
        }
    }

    pub fn list(&self) -> Result<(), Box<dyn Error>> {
        if self.passwords.is_empty() {
            return Err("No passwords found".into());
        }

        let mut t = Table::new(vec!["Labels".into(), "Passwords".into()]);

        for (label, (nonce, password)) in self.passwords.clone() {
            let nonce = Nonce::from_slice(&nonce);
            let plaintext = match self.cipher.decrypt(nonce, password.as_slice()) {
                Ok(v) => v,
                Err(e) => return Err(format!("Error ocuured while decryption: {}", e).into()),
            };

            t.insert(vec![label, String::from_utf8(plaintext)?]);
        }

        t.display()?;

        Ok(())
    }

    pub fn reset(&mut self) -> Result<(), Box<dyn Error>> {
        scan!("Are you sure you want to reset passwords? (y/n): ", conf);
        if conf == "y" {
            self.passwords = BTreeMap::new();
        }

        Ok(())
    }

    pub fn gen(&mut self, label: String, len: usize) -> Result<(), Box<dyn Error>> {
        let mut rng = rand::thread_rng();
        scan!("Do you want special chars? (y/n): ", choice);
        let range = if choice == "y" { 94 } else { 62 };
        let password_charset = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

        let mut password = String::with_capacity(len);
        for _ in 0..len {
            let pos = rng.gen_range(0..range);
            password.push(char::from_u32(password_charset[pos] as u32).unwrap())
        }

        println!("{password}");

        self.add(label, password)
    }

    pub fn create(&mut self, username: String, password: String) -> Result<(), Box<dyn Error>> {
        let salt: [u8; 16] = rand::random();

        let mut salted = salt.to_vec();
        salted.extend_from_slice(password.as_bytes());

        Users::create(self.path.with_extension(username.clone()), username.clone(), salt, Sha3_256::digest(&salted).into())?;

        std::fs::write(self.path.with_extension(username), rkyv::to_bytes::<_, 1024>(&BTreeMap::<String, ([u8; 12], Vec<u8>)>::new())?)?;
        Ok(())
    }

    pub fn change(&mut self, cur_key: String, new_key: String) -> Result<(), Box<dyn Error>> {
        let sha_path  = self.path.with_extension("sha");
        let mut f = OpenOptions::new().write(true).read(true).open(sha_path)?;

        f.seek(SeekFrom::Start(0))?;

        let mut salt: [u8; 16] = [0; 16];
        f.read_exact(&mut salt)?;

        let mut hash: [u8; 32] = [0; 32];
        f.read_exact(&mut hash)?;

        let mut salted = salt.to_vec();
        salted.extend_from_slice(&cur_key.as_bytes());

        let cur_key_hash = Sha256::digest(&salted);

        if cur_key_hash.as_slice() == hash {
            let salt: [u8; 16] = rand::random();

            let mut salted = salt.to_vec();
            salted.extend_from_slice(new_key.as_bytes());

            let new_key_hash = Sha256::digest(&salted);

            f.seek(SeekFrom::Start(0))?;

            f.write_all(&salt)?;
            f.write_all(&new_key_hash)?;

            self.cipher = Aes256Gcm::new(&new_key_hash);

            Ok(())
        } else {
            Err("Incorrect password".into())
        }
    }
}

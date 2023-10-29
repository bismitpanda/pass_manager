use clipboard::{ClipboardContext, ClipboardProvider};
use std::{
    collections::{
        btree_map::Entry::{Occupied, Vacant},
        BTreeMap,
    },
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};

use rand::Rng;
use sha2::{Digest, Sha256};

use crate::table::Table;

macro_rules! scan {
    ($var:expr, $ident:tt) => {
        print!("{}", $var);
        std::io::stdout().flush().unwrap();
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).unwrap();
        let $ident = String::from(line.trim_end());
    };
}

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[archive(check_bytes)]
pub struct PasswordEntry {
    nonce: [u8; 12],
    password: Vec<u8>,
}

impl PasswordEntry {
    pub fn new(salt: [u8; 12], password_encrypted: Vec<u8>) -> Self {
        Self {
            nonce: salt,
            password: password_encrypted,
        }
    }
}

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[archive(check_bytes)]
struct Store {
    salt: [u8; 16],
    passwords: BTreeMap<String, PasswordEntry>,
}

impl Store {
    fn new(salt: [u8; 16], passwords: BTreeMap<String, PasswordEntry>) -> Self {
        Self { salt, passwords }
    }

    fn open<P: AsRef<Path>>(path: P) -> Self {
        let buf = std::fs::read(path).unwrap();
        rkyv::from_bytes::<Self>(&buf).unwrap()
    }

    fn save<P: AsRef<Path>>(&self, path: P) {
        let data = rkyv::to_bytes::<_, 1024>(self).unwrap();
        std::fs::write(path, &data).unwrap();
    }

    fn is_empty(&self) -> bool {
        self.passwords.is_empty()
    }

    fn remove(&mut self, label: &str) -> bool {
        self.passwords.remove(label).is_some()
    }
}

pub struct PasswordManager {
    store: Store,
    cipher: Aes256Gcm,
    path: PathBuf,
}

impl PasswordManager {
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        let path = path.as_ref();

        if path.exists() {
            let store = Store::open(path);
            let key = rpassword::prompt_password("Your key: ").unwrap();

            let mut salted = store.salt.to_vec();
            salted.extend_from_slice(key.as_bytes());

            let cipher_key = Sha256::digest(&salted);
            let cipher = Aes256Gcm::new(cipher_key.as_slice().into());

            Self {
                store,
                cipher,
                path: path.to_path_buf(),
            }
        } else {
            File::create(path).unwrap();
            let key = rpassword::prompt_password("Enter a key: ").unwrap();
            let salt: [u8; 16] = rand::random();

            let mut salted = salt.to_vec();
            salted.extend_from_slice(key.as_bytes());

            let cipher_key = Sha256::digest(&salted);

            Self {
                store: Store::new(salt, BTreeMap::new()),
                cipher: Aes256Gcm::new(&cipher_key),
                path: path.to_path_buf(),
            }
        }
    }

    pub fn add(&mut self, label: &str, password: &str) {
        let nonce_slice: [u8; 12] = rand::random();

        let nonce = Nonce::from_slice(&nonce_slice);

        let ciphertext = self
            .cipher
            .encrypt(nonce, password.as_bytes().as_ref())
            .unwrap();

        match self.store.passwords.entry(label.to_string()) {
            Vacant(entry) => {
                entry.insert(PasswordEntry::new(nonce_slice, ciphertext));
            }
            Occupied(mut entry) => {
                scan!(
                    format!("A password exists for \"{label}\". Do you want to overwrite? (y/n)"),
                    choice
                );
                if choice == "y" {
                    entry.insert(PasswordEntry::new(nonce_slice, ciphertext));
                }
            }
        };
    }

    pub fn remove(&mut self, label: &str) {
        if !self.store.remove(label) {
            println!("No entry found with label \"{label}\" ");
        }
    }

    pub fn copy(&self, label: &str) {
        let Some(PasswordEntry { nonce, password }) = self.store.passwords.get(label) else {
            return println!("No passwords found with label \"{label}\"");
        };

        let nonce = Nonce::from_slice(nonce);

        let plaintext = self.cipher.decrypt(nonce, password.as_slice()).unwrap();
        let mut clipboard: ClipboardContext = ClipboardProvider::new().unwrap();

        clipboard
            .set_contents(String::from_utf8(plaintext).unwrap())
            .unwrap();
    }

    pub fn list(&self) {
        if self.store.is_empty() {
            return println!("No passwords found");
        }

        let mut t = Table::new(vec!["Labels".into(), "Passwords".into()]);

        for (label, PasswordEntry { nonce, password }) in &self.store.passwords {
            let nonce = Nonce::from_slice(nonce);
            let plaintext = self.cipher.decrypt(nonce, password.as_slice()).unwrap();

            t.insert(vec![
                label.to_owned(),
                String::from_utf8(plaintext).unwrap(),
            ]);
        }

        t.display();
    }

    pub fn gen(len: usize) -> String {
        let mut rng = rand::thread_rng();
        scan!("Do you want special chars? (y/n): ", choice);
        let range = if choice == "y" { 94 } else { 62 };
        let password_charset = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

        let mut password = String::with_capacity(len);
        for _ in 0..len {
            let pos = rng.gen_range(0..range);
            password.push(char::from_u32(u32::from(password_charset[pos])).unwrap());
        }

        password
    }
}

impl Drop for PasswordManager {
    fn drop(&mut self) {
        self.store.save(&self.path);
    }
}

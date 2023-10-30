use std::{
    fs::File,
    path::{Path, PathBuf},
};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use clipboard::{ClipboardContext, ClipboardProvider};
use hashbrown::{
    hash_map::Entry::{Occupied, Vacant},
    HashMap,
};
use sha2::{Digest, Sha256};

use crate::table::Table;

macro_rules! scan {
    ($var:expr, $ident:tt) => {
        println!("{}", $var);
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).unwrap();
        let $ident = line.trim();
    };
}

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[archive(check_bytes)]
pub struct Record {
    nonce: [u8; 12],
    password: Vec<u8>,
}

impl Record {
    pub fn new(nonce: [u8; 12], password: Vec<u8>) -> Self {
        Self { nonce, password }
    }
}

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[archive(check_bytes)]
struct Store {
    salt: [u8; 16],
    passwords: HashMap<String, Record>,
}

impl Store {
    fn new(salt: [u8; 16]) -> Self {
        Self {
            salt,
            passwords: HashMap::new(),
        }
    }

    fn open(path: &Path) -> Self {
        let buf = std::fs::read(path).unwrap();
        rkyv::from_bytes::<Self>(&buf).unwrap()
    }

    fn save(&self, path: &Path) {
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

pub struct Manager {
    store: Store,
    cipher: Aes256Gcm,
    path: PathBuf,
}

impl Manager {
    pub fn new(path: &Path) -> Self {
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
            println!("Created store file at '{}'", path.display());

            let key = rpassword::prompt_password("Enter a key: ").unwrap();
            let salt: [u8; 16] = rand::random();

            let mut salted = salt.to_vec();
            salted.extend_from_slice(key.as_bytes());

            let cipher_key = Sha256::digest(&salted);

            Self {
                store: Store::new(salt),
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
                entry.insert(Record::new(nonce_slice, ciphertext));
            }
            Occupied(mut entry) => {
                scan!("Overwrite existing password? (y/n) ", choice);
                if choice == "y" {
                    entry.insert(Record::new(nonce_slice, ciphertext));
                }
            }
        };
    }

    pub fn remove(&mut self, label: &str) {
        if !self.store.remove(label) {
            println!("No entry found");
        }
    }

    pub fn copy(&self, label: &str) {
        let Some(Record { nonce, password }) = self.store.passwords.get(label) else {
            return println!("No entry found");
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
            return println!("Empty store");
        }

        let mut t = Table::new(["Labels".into(), "Passwords".into()]);

        for (label, Record { nonce, password }) in &self.store.passwords {
            let nonce = Nonce::from_slice(nonce);
            let plaintext = self.cipher.decrypt(nonce, password.as_slice()).unwrap();

            t.insert([label.to_owned(), String::from_utf8(plaintext).unwrap()]);
        }

        t.display();
    }
}

impl Drop for Manager {
    fn drop(&mut self) {
        self.store.save(&self.path);
    }
}

pub fn gen_password(len: usize, special_chars: bool) -> String {
    let mut rng = rand::thread_rng();

    let password_charset = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
    let indices =
        rand::seq::index::sample(&mut rng, if special_chars { 94 } else { 62 }, len).into_vec();

    let mut password = Vec::with_capacity(len);
    for index in indices {
        password.push(password_charset[index]);
    }

    String::from_utf8(password).unwrap()
}

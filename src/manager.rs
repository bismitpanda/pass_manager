use std::{fs::File, path::PathBuf};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use clipboard::{ClipboardContext, ClipboardProvider};
use hashbrown::{hash_map::Entry, HashMap};
use rand::seq::SliceRandom;
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
    key: Vec<u8>,
    nonce: [u8; 12],
    salt: [u8; 16],
    passwords: HashMap<String, Record>,
}

impl Store {
    fn new(key: Vec<u8>, salt: [u8; 16], nonce: [u8; 12]) -> Self {
        Self {
            nonce,
            key,
            salt,
            passwords: HashMap::new(),
        }
    }

    fn open(path: &PathBuf) -> Self {
        let buf = std::fs::read(path).unwrap();
        rkyv::from_bytes::<Self>(&buf).unwrap()
    }

    fn save(&self, path: &PathBuf) {
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
    key_cipher: Aes256Gcm,
}

impl Manager {
    pub fn new(path: PathBuf) -> Self {
        if path.exists() {
            let store = Store::open(&path);
            let key = rpassword::prompt_password("Your key: ").unwrap();

            let mut salted = store.salt.to_vec();
            salted.extend_from_slice(key.as_bytes());

            let cipher_key = Sha256::digest(&salted);
            let key_cipher = Aes256Gcm::new(cipher_key.as_slice().into());

            let key = key_cipher
                .decrypt(&store.nonce.into(), store.key.as_slice())
                .unwrap();

            let key: [u8; 32] = key.as_slice().try_into().unwrap();

            let cipher = Aes256Gcm::new(&key.into());

            Self {
                store,
                cipher,
                path,
                key_cipher,
            }
        } else {
            File::create(&path).unwrap();
            println!("Created store file at '{}'", path.display());

            let user_key = rpassword::prompt_password("Enter a key: ").unwrap();
            let salt: [u8; 16] = rand::random();

            let mut salted = salt.to_vec();
            salted.extend_from_slice(user_key.as_bytes());

            let cipher_key = Sha256::digest(&salted);

            let key_cipher = Aes256Gcm::new(&cipher_key);
            let key: [u8; 32] = rand::random();
            let nonce_slice: [u8; 12] = rand::random();

            let nonce = Nonce::from_slice(&nonce_slice);

            let encrypted_key = key_cipher.encrypt(nonce, &key[..]).unwrap();

            Self {
                store: Store::new(encrypted_key, salt, nonce_slice),
                cipher: Aes256Gcm::new(&key.into()),
                path,
                key_cipher,
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
            Entry::Vacant(entry) => {
                entry.insert(Record::new(nonce_slice, ciphertext));
            }
            Entry::Occupied(mut entry) => {
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

        let plaintext = self
            .cipher
            .decrypt(nonce.into(), password.as_slice())
            .unwrap();

        let mut clipboard: ClipboardContext = ClipboardProvider::new().unwrap();

        clipboard
            .set_contents(String::from_utf8(plaintext).unwrap())
            .unwrap();
    }

    pub fn list(&self) {
        if self.store.is_empty() {
            return println!("Empty store");
        }

        let mut t = Table::new(["Labels".to_owned(), "Passwords".to_owned()]);

        for (label, Record { nonce, password }) in &self.store.passwords {
            let nonce = Nonce::from_slice(nonce);
            let plaintext = self.cipher.decrypt(nonce, password.as_slice()).unwrap();

            t.insert([label.to_owned(), String::from_utf8(plaintext).unwrap()]);
        }

        t.display();
    }

    pub fn modify(&mut self, new_key: &str) {
        let enc_key = self
            .key_cipher
            .decrypt(&self.store.nonce.into(), self.store.key.as_slice())
            .unwrap();

        let new_salt: [u8; 16] = rand::random();
        let new_nonce: [u8; 12] = rand::random();

        self.store.nonce = new_nonce;
        self.store.salt = new_salt;

        let mut salted = new_salt.to_vec();
        salted.extend_from_slice(new_key.as_bytes());

        let new_cipher_key = Sha256::digest(&salted);
        let new_key_cipher = Aes256Gcm::new(&new_cipher_key);

        let new_key = new_key_cipher
            .encrypt(&new_nonce.into(), enc_key.as_slice())
            .unwrap();

        self.store.key = new_key;
    }
}

impl Drop for Manager {
    fn drop(&mut self) {
        self.store.save(&self.path);
    }
}

pub fn gen_password(len: usize, special_chars: bool) -> String {
    let password_charset = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
    let mut rng = rand::thread_rng();

    let subset = &password_charset[..(special_chars.then_some(94).unwrap_or(62))];
    let password = subset.choose_multiple(&mut rng, len).map(|x| *x).collect();

    String::from_utf8(password).unwrap()
}

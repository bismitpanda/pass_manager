use std::path::PathBuf;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm,
};
use argon2::Argon2;
use dialoguer::{theme::ColorfulTheme, Confirm, Password};
use hashbrown::HashMap;

use crate::manager::{length_validator, Manager};

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct Item {
    pub nonce: [u8; 12],
    pub password: Vec<u8>,
}

impl Item {
    pub fn new(nonce: [u8; 12], password: Vec<u8>) -> Self {
        Self { nonce, password }
    }
}

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct Store {
    pub key: Vec<u8>,
    pub nonce: [u8; 12],
    pub salt: [u8; 16],
    pub items: HashMap<String, Item>,
}

impl Store {
    pub fn new(key: Vec<u8>, salt: [u8; 16], nonce: [u8; 12]) -> Self {
        Self {
            nonce,
            key,
            salt,
            items: HashMap::new(),
        }
    }

    pub fn open(path: &PathBuf) -> Self {
        let buf = std::fs::read(path).unwrap();
        unsafe { rkyv::from_bytes_unchecked::<Self>(&buf).unwrap() }
    }

    pub fn save(&self, path: &PathBuf) {
        let data = rkyv::to_bytes::<_, 1024>(self).unwrap();
        std::fs::write(path, &data).unwrap();
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn delete(&mut self, label: &str) -> bool {
        self.items.remove(label).is_some()
    }
}

impl Manager {
    pub fn reset(&mut self) {
        if Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Do you want to reset?")
            .interact()
            .unwrap()
        {
            self.store.items = HashMap::new();
        }
    }

    pub fn modify(&mut self) {
        let new_key = Password::with_theme(&ColorfulTheme::default())
            .with_prompt("Enter new key")
            .with_confirmation("Retype new key", "keys do not match")
            .validate_with(length_validator)
            .interact()
            .unwrap();

        let enc_key = self
            .key_aes
            .decrypt(&self.store.nonce.into(), self.store.key.as_slice())
            .unwrap();

        let new_salt: [u8; 16] = rand::random();
        let new_nonce: [u8; 12] = rand::random();

        self.store.nonce = new_nonce;
        self.store.salt = new_salt;

        let mut new_cipher_key: [u8; 32] = [0; 32];
        Argon2::default()
            .hash_password_into(new_key.as_bytes(), &new_salt, &mut new_cipher_key)
            .unwrap();

        let new_key_cipher = Aes256Gcm::new(&new_cipher_key.into());

        let new_key = new_key_cipher
            .encrypt(&new_nonce.into(), enc_key.as_slice())
            .unwrap();

        self.store.key = new_key;
    }
}

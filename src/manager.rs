use std::{fs::File, path::PathBuf};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::Argon2;
use clipboard::{ClipboardContext, ClipboardProvider};
use dialoguer::{theme::ColorfulTheme, Confirm, Password};
use hashbrown::hash_map::Entry;
use owo_colors::OwoColorize;
use rand::seq::SliceRandom;

use crate::{
    store::{Item, Record, Store},
    table::Table,
};

pub struct Manager {
    pub store: Store,
    pub store_cipher: Aes256Gcm,
    pub bin_path: PathBuf,
    pub key_cipher: Aes256Gcm,
}

pub fn length_validator(inp: &String) -> Result<(), String> {
    (inp.len() > 8)
        .then_some(())
        .ok_or_else(|| "Password must be longer than 8".into())
}

impl Manager {
    pub fn new(bin_path: PathBuf) -> Self {
        if bin_path.exists() {
            let store = Store::open(&bin_path);
            let key = Password::with_theme(&ColorfulTheme::default())
                .with_prompt("Your key")
                .validate_with(length_validator)
                .interact()
                .unwrap();

            let mut derived_key = [0u8; 32];
            Argon2::default()
                .hash_password_into(key.as_bytes(), &store.salt, &mut derived_key)
                .unwrap();

            let key_cipher = Aes256Gcm::new(derived_key.as_slice().into());

            let key = key_cipher
                .decrypt(&store.nonce.into(), store.key.as_slice())
                .unwrap();

            let key: [u8; 32] = key.as_slice().try_into().unwrap();

            let store_cipher = Aes256Gcm::new(&key.into());

            Self {
                store,
                store_cipher,
                bin_path,
                key_cipher,
            }
        } else {
            File::create(&bin_path).unwrap();
            println!("Created store file at '{}'", bin_path.display());

            let user_key = Password::with_theme(&ColorfulTheme::default())
                .with_prompt("Your key")
                .with_confirmation("Retype key", "Passwords do not match")
                .interact()
                .unwrap();

            let salt: [u8; 16] = rand::random();

            let mut derived_key = [0u8; 32];
            Argon2::default()
                .hash_password_into(user_key.as_bytes(), &salt, &mut derived_key)
                .unwrap();

            let key_cipher = Aes256Gcm::new(&derived_key.into());

            let key: [u8; 32] = rand::random();
            let nonce_slice: [u8; 12] = rand::random();
            let nonce = Nonce::from_slice(&nonce_slice);

            let encrypted_key = key_cipher.encrypt(nonce, &key[..]).unwrap();

            Self {
                store: Store::new(encrypted_key, salt, nonce_slice),
                store_cipher: Aes256Gcm::new(&key.into()),
                bin_path,
                key_cipher,
            }
        }
    }

    pub fn add(
        &mut self,
        label: &str,
        input: bool,
        len: usize,
        special_chars: bool,
        overwrite: bool,
    ) {
        let password = if input {
            Password::with_theme(&ColorfulTheme::default())
                .with_prompt("Enter your password")
                .validate_with(length_validator)
                .interact()
                .unwrap()
        } else {
            let password_charset = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
            let mut rng = rand::thread_rng();

            let subset = &password_charset[..(if special_chars { 94 } else { 62 })];
            let password = subset.choose_multiple(&mut rng, len).copied().collect();

            String::from_utf8(password).unwrap()
        };

        let nonce_slice: [u8; 12] = rand::random();
        let nonce = Nonce::from_slice(&nonce_slice);

        let ciphertext = self
            .store_cipher
            .encrypt(nonce, password.as_bytes().as_ref())
            .unwrap();

        match self.store.items.entry(label.to_string()) {
            Entry::Vacant(entry) => {
                entry.insert(Item::new(Record::new(nonce_slice, ciphertext)));
            }

            Entry::Occupied(mut entry) => {
                let confirmed = overwrite
                    || Confirm::with_theme(&ColorfulTheme::default())
                        .with_prompt("Do you want to modify?")
                        .interact()
                        .unwrap();
                if confirmed {
                    entry.insert(Item::new(Record::new(nonce_slice, ciphertext)));
                }
            }
        };
    }

    pub fn purge(&mut self, label: &str) {
        if !self.store.delete(label) {
            println!("{}", "No item found".bright_red());
        }
    }

    pub fn delete(&mut self, label: String) {
        match self.store.items.entry(label) {
            Entry::Occupied(mut entry) if !entry.get().is_deleted => {
                entry.get_mut().is_deleted = true;
            }
            Entry::Occupied(_) => println!("{}", "Item already deleted from store".bright_red()),
            Entry::Vacant(_) => println!("{}", "No item found in store".bright_red()),
        }
    }

    pub fn copy(&self, label: &str) {
        let Some(item) = self.store.items.get(label) else {
            return println!("No item found in store");
        };

        if item.is_deleted {
            return println!("Item is deleted");
        }

        let Record {
            nonce, password, ..
        } = &item.record;

        let plaintext = self
            .store_cipher
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

        for (label, item) in self.store.items.iter().filter(|&(_, v)| !v.is_deleted) {
            let Record { nonce, password } = &item.record;

            let nonce = Nonce::from_slice(nonce);
            let plaintext = self
                .store_cipher
                .decrypt(nonce, password.as_slice())
                .unwrap();

            t.insert([label.to_owned(), String::from_utf8(plaintext).unwrap()]);
        }

        t.display();
    }

    pub fn restore(&mut self, label: &str) {
        let Some(item) = self.store.items.get_mut(label) else {
            return println!("{}", "No item found in store".bright_red());
        };

        if !item.is_deleted {
            return println!("{}", "Item is not deleted from store".bright_yellow());
        }

        item.is_deleted = false;
    }
}

impl Drop for Manager {
    fn drop(&mut self) {
        self.store.save(&self.bin_path);
    }
}

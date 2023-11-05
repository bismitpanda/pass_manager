use std::{io::Read, path::PathBuf};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm,
};
use argon2::Argon2;
use dialoguer::{theme::ColorfulTheme, Confirm, Password};
use hashbrown::HashMap;
use serde_with::{formats::Uppercase, hex::Hex, serde_as};

use crate::{
    cmd::SupportedFormat,
    manager::{length_validator, Manager},
};

#[serde_as]
#[derive(
    rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, serde::Deserialize, serde::Serialize, Clone,
)]
pub struct Record {
    pub time: chrono::DateTime<chrono::Local>,
    #[serde_as(as = "Hex<Uppercase>")]
    pub nonce: [u8; 12],
    #[serde_as(as = "Hex<Uppercase>")]
    pub password: Vec<u8>,
}

impl Record {
    pub fn new(nonce: [u8; 12], password: Vec<u8>) -> Self {
        Self {
            time: chrono::Local::now(),
            nonce,
            password,
        }
    }
}

#[derive(
    rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, serde::Deserialize, serde::Serialize, Clone,
)]
pub struct Item {
    pub is_deleted: bool,
    pub records: Vec<Record>,
}

impl Item {
    pub fn new(record: Record) -> Self {
        Self {
            is_deleted: false,
            records: vec![record],
        }
    }

    pub fn add_record(&mut self, record: Record) {
        self.records.push(record);
    }

    pub fn curr(&self) -> &Record {
        self.records.last().unwrap()
    }
}

#[serde_as]
#[derive(
    rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, serde::Deserialize, serde::Serialize,
)]
pub struct Store {
    #[serde_as(as = "Hex<Uppercase>")]
    pub key: Vec<u8>,
    #[serde_as(as = "Hex<Uppercase>")]
    pub nonce: [u8; 12],
    #[serde_as(as = "Hex<Uppercase>")]
    pub salt: [u8; 16],
    pub passwords: HashMap<String, Item>,
}

impl Store {
    pub fn new(key: Vec<u8>, salt: [u8; 16], nonce: [u8; 12]) -> Self {
        Self {
            nonce,
            key,
            salt,
            passwords: HashMap::new(),
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
        self.passwords.is_empty()
    }

    pub fn delete(&mut self, label: &str) -> bool {
        self.passwords.remove(label).is_some()
    }
}

impl Manager {
    pub fn reset(&mut self) {
        if Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Do you want to reset?")
            .interact()
            .unwrap()
        {
            self.store.passwords = HashMap::new();
        }
    }

    pub fn modify(&mut self) {
        let new_key = Password::with_theme(&ColorfulTheme::default())
            .with_prompt("Enter new key")
            .with_confirmation("Repeat key", "Error: the keys don't match.")
            .validate_with(length_validator)
            .interact()
            .unwrap();

        let enc_key = self
            .key_cipher
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

    pub fn export(&self, format: SupportedFormat, out_file: Option<PathBuf>, pretty: bool) {
        let output = match format {
            SupportedFormat::Json => {
                if pretty {
                    json::to_string_pretty(&self.store).unwrap()
                } else {
                    json::to_string(&self.store).unwrap()
                }
            }
            SupportedFormat::Yaml => yaml::to_string(&self.store).unwrap(),
            SupportedFormat::Toml => {
                if pretty {
                    toml::to_string_pretty(&self.store).unwrap()
                } else {
                    toml::to_string(&self.store).unwrap()
                }
            }
            SupportedFormat::Ron => {
                if pretty {
                    ron::ser::to_string_pretty(&self.store, ron::ser::PrettyConfig::default())
                        .unwrap()
                } else {
                    ron::to_string(&self.store).unwrap()
                }
            }
        };

        out_file.map_or_else(
            || println!("{output}"),
            |out_file| std::fs::write(out_file, &output).unwrap(),
        );
    }

    pub fn import(&mut self, format: SupportedFormat, in_file: Option<PathBuf>) {
        let input = in_file.map_or_else(
            || {
                let mut buf = String::new();
                std::io::stdin().lock().read_to_string(&mut buf).unwrap();

                buf
            },
            |in_file| std::fs::read_to_string(in_file).unwrap(),
        );

        self.store = match format {
            SupportedFormat::Json => json::from_str(&input).unwrap(),
            SupportedFormat::Yaml => yaml::from_str(&input).unwrap(),
            SupportedFormat::Toml => toml::from_str(&input).unwrap(),
            SupportedFormat::Ron => ron::from_str(&input).unwrap(),
        };
    }

    pub fn clean(&mut self) {
        let not_deleted = self
            .store
            .passwords
            .iter()
            .filter_map(|(k, v)| (!v.is_deleted).then_some((k.clone(), v.clone())))
            .collect::<HashMap<_, _>>();

        self.store.passwords = not_deleted
    }
}

use std::{
    io::prelude::*,
    path::PathBuf,
    process::{Command, Stdio},
};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm,
};
use argon2::Argon2;
use dialoguer::{theme::ColorfulTheme, Confirm, Password};
use git2::{Cred, Direction, PushOptions, RemoteCallbacks};
use hashbrown::HashMap;
use url::Url;

use crate::manager::{length_validator, Manager};

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[archive(check_bytes)]
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
#[archive(check_bytes)]
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
        rkyv::from_bytes::<Self>(&buf).unwrap()
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

        self.store_dirty = true;
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

        self.store_dirty = true;
    }

    pub fn sync(&self) {
        let Some(url) = &self.user.remote else {
            return println!("Remote not set");
        };

        let mut remote = self.repo.find_remote("origin").unwrap();
        remote.connect(Direction::Push).unwrap();

        let mut push_options = PushOptions::new();

        let mut callbacks = RemoteCallbacks::new();
        callbacks.credentials(|_, _, _| {
            let cred = get_remote_credentials(&get_host_from_url(url));
            Cred::userpass_plaintext(&cred["username"], &cred["password"])
        });

        push_options.remote_callbacks(callbacks);

        remote
            .push(
                &["refs/heads/master:refs/heads/master"],
                Some(&mut push_options),
            )
            .unwrap();
    }
}

fn get_remote_credentials(host: &str) -> HashMap<String, String> {
    let command = Command::new("git")
        .args(&["credential", "fill"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();

    command
        .stdin
        .unwrap()
        .write_all(format!("protocol=https\nhost={}", host).as_bytes())
        .unwrap();

    let mut s = String::new();
    command.stdout.unwrap().read_to_string(&mut s).unwrap();

    let mut config = HashMap::new();

    for line in s.split_terminator("\n") {
        let (k, v) = line.split_once('=').unwrap();
        config.insert(k.into(), v.into());
    }

    config
}

fn get_host_from_url(url: &str) -> String {
    let url = Url::parse(url).unwrap();

    url.host_str().unwrap().to_string()
}

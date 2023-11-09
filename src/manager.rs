use std::path::{Path, PathBuf};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::Argon2;
use clipboard::{ClipboardContext, ClipboardProvider};
use dialoguer::{theme::ColorfulTheme, Confirm, Input, Password};
use git2::{ObjectType, Repository, Signature};
use hashbrown::hash_map::Entry;
use owo_colors::OwoColorize;
use rand::seq::SliceRandom;

use crate::{
    store::{Item, Store},
    table::Table,
    user::{validate_email, validate_url, User},
};

pub struct Manager {
    pub repo: Repository,
    pub data_dir: PathBuf,

    pub key_aes: Aes256Gcm,
    pub store_aes: Aes256Gcm,

    pub store: Store,
    pub user: User,

    pub store_dirty: bool,
    pub user_dirty: bool,
}

pub fn length_validator(inp: &String) -> Result<(), String> {
    (inp.len() > 8)
        .then_some(())
        .ok_or_else(|| "Password must be longer than 8".into())
}

const STORE_BIN_PATH: &str = "pm_store.bin";
const USER_BIN_PATH: &str = "user.bin";

impl Manager {
    pub fn new(data_dir: PathBuf) -> Self {
        if data_dir.exists() {
            Self::open(data_dir)
        } else {
            Self::create(data_dir)
        }
    }

    pub fn open(data_dir: PathBuf) -> Self {
        let store = Store::open(&data_dir.join(STORE_BIN_PATH));
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

        let repo = Repository::open(&data_dir).unwrap();
        let user = User::open(&data_dir.join(USER_BIN_PATH));

        Self {
            store,
            store_aes: store_cipher,
            data_dir,
            key_aes: key_cipher,
            repo,
            user,
            store_dirty: false,
            user_dirty: false,
        }
    }

    pub fn create(data_dir: PathBuf) -> Self {
        std::fs::create_dir(&data_dir).unwrap();

        let user_key = Password::with_theme(&ColorfulTheme::default())
            .with_prompt("Enter new key")
            .with_confirmation("Retype key", "keys do not match")
            .interact()
            .unwrap();

        let salt: [u8; 16] = rand::random();

        let mut derived_key = [0u8; 32];
        Argon2::default()
            .hash_password_into(user_key.as_bytes(), &salt, &mut derived_key)
            .unwrap();

        let key_aes = Aes256Gcm::new(&derived_key.into());

        let key: [u8; 32] = rand::random();
        let nonce_slice: [u8; 12] = rand::random();
        let nonce = Nonce::from_slice(&nonce_slice);

        let encrypted_key = key_aes.encrypt(nonce, &key[..]).unwrap();

        let name = Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Enter username")
            .default(whoami::realname())
            .interact()
            .unwrap();

        let email = Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Enter email")
            .validate_with(validate_email)
            .interact()
            .unwrap();

        let remote = if Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Do you want to enter a remote service")
            .interact()
            .unwrap()
        {
            let url = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("Enter remote url")
                .validate_with(validate_url)
                .interact()
                .unwrap();

            Some(url)
        } else {
            None
        };

        let user = User {
            name,
            email,
            remote,
        };

        let store = Store::new(encrypted_key, salt, nonce_slice);

        user.save(&data_dir.join(USER_BIN_PATH));
        store.save(&data_dir.join(STORE_BIN_PATH));

        let repo = Repository::init(&data_dir).unwrap();

        if let Some(remote) = &user.remote {
            repo.remote("origin", remote).unwrap();
        }

        let mut index = repo.index().unwrap();

        index.add_path(Path::new(STORE_BIN_PATH)).unwrap();
        index.add_path(Path::new(USER_BIN_PATH)).unwrap();

        let oid = index.write_tree().unwrap();
        let signature = Signature::now(&user.name, &user.email).unwrap();

        repo.commit(
            Some("HEAD"),
            &signature,
            &signature,
            "Initialize store",
            &repo.find_tree(oid).unwrap(),
            &[],
        )
        .unwrap();

        Self {
            store,
            store_aes: Aes256Gcm::new(&key.into()),
            data_dir,
            key_aes,
            repo,
            user,
            store_dirty: false,
            user_dirty: false,
        }
    }
}

impl Manager {
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
            .store_aes
            .encrypt(nonce, password.as_bytes().as_ref())
            .unwrap();

        match self.store.items.entry(label.to_string()) {
            Entry::Vacant(entry) => {
                entry.insert(Item::new(nonce_slice, ciphertext));
            }

            Entry::Occupied(mut entry) => {
                let confirmed = overwrite
                    || Confirm::with_theme(&ColorfulTheme::default())
                        .with_prompt("Do you want to modify?")
                        .interact()
                        .unwrap();
                if confirmed {
                    entry.insert(Item::new(nonce_slice, ciphertext));
                }
            }
        };

        self.store_dirty = true;
    }

    pub fn delete(&mut self, label: &str) {
        if self.store.items.remove(label).is_none() {
            println!("{}", "No item found in store".bright_red());
        }

        self.store_dirty = true;
    }

    pub fn copy(&self, label: &str) {
        let Some(item) = self.store.items.get(label) else {
            return println!("No item found in store");
        };

        let Item {
            nonce, password, ..
        } = &item;

        let plaintext = self
            .store_aes
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

        for (label, item) in &self.store.items {
            let Item { nonce, password } = &item;

            let nonce = Nonce::from_slice(nonce);
            let plaintext = self.store_aes.decrypt(nonce, password.as_slice()).unwrap();

            t.insert([label.to_owned(), String::from_utf8(plaintext).unwrap()]);
        }

        t.display();
    }
}

impl Manager {
    pub fn save(&self, message: &str) {
        if !(self.store_dirty || self.user_dirty) {
            return;
        }

        let mut index = self.repo.index().unwrap();

        if self.store_dirty {
            self.store.save(&self.data_dir.join(STORE_BIN_PATH));
            index.add_path(Path::new(STORE_BIN_PATH)).unwrap();
        }

        if self.user_dirty {
            self.user.save(&self.data_dir.join(USER_BIN_PATH));
            index.add_path(Path::new(USER_BIN_PATH)).unwrap();
        }

        let oid = index.write_tree().unwrap();
        let signature = Signature::now(&self.user.name, &self.user.email).unwrap();
        let parent_commit = self
            .repo
            .head()
            .unwrap()
            .resolve()
            .unwrap()
            .peel(ObjectType::Commit)
            .unwrap()
            .into_commit()
            .unwrap();

        let tree = self.repo.find_tree(oid).unwrap();
        self.repo
            .commit(
                Some("HEAD"),
                &signature,
                &signature,
                message,
                &tree,
                &[&parent_commit],
            )
            .unwrap();
    }
}

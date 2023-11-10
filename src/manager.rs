use std::path::{Path, PathBuf};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::Argon2;
use clipboard::{ClipboardContext, ClipboardProvider};
use dialoguer::{theme::ColorfulTheme, Confirm, Input, Password};
use git2::{Config, ObjectType, Repository, RepositoryInitOptions, Signature};
use hashbrown::hash_map::Entry;
use owo_colors::OwoColorize;
use rand::seq::SliceRandom;
use snafu::{OptionExt, ResultExt};

use crate::{
    error::{FsErr, InvalidCommitMessageErr, Result},
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
    pub user_nonce: [u8; 12],

    pub store_dirty: bool,
    pub user_dirty: bool,
}

pub fn length_validator(inp: &str) -> Result<(), String> {
    (inp.len() >= 8)
        .then_some(())
        .ok_or_else(|| "Password must be longer than 8".to_string())
}

const STORE_BIN_PATH: &str = "pm_store.bin";
const USER_BIN_PATH: &str = "user.bin";

impl Manager {
    pub fn new(data_dir: PathBuf) -> Result<Self> {
        if data_dir.exists() {
            Self::open(data_dir)
        } else {
            Self::create(data_dir)
        }
    }

    pub fn open(data_dir: PathBuf) -> Result<Self> {
        let store = Store::open(&data_dir.join(STORE_BIN_PATH))?;
        let key = Password::with_theme(&ColorfulTheme::default())
            .with_prompt("Your key")
            .validate_with(|inp: &String| length_validator(inp))
            .interact()?;

        let mut derived_key = [0u8; 32];
        Argon2::default().hash_password_into(key.as_bytes(), &store.salt, &mut derived_key)?;

        let key_aes = Aes256Gcm::new(derived_key.as_slice().into());

        let key = key_aes.decrypt(&store.nonce.into(), store.key.as_slice())?;

        let key: [u8; 32] = key.as_slice().try_into()?;

        let store_aes = Aes256Gcm::new(&key.into());

        let repo = Repository::open(&data_dir)?;
        let (user_nonce, user) = User::open(&data_dir.join(USER_BIN_PATH), &store_aes)?;

        Ok(Self {
            store,
            store_aes,
            data_dir,
            key_aes,
            repo,
            user,
            user_nonce,
            store_dirty: false,
            user_dirty: false,
        })
    }

    pub fn create(data_dir: PathBuf) -> Result<Self> {
        std::fs::create_dir(&data_dir).context(FsErr {
            path: data_dir.display().to_string(),
        })?;

        let user_key = Password::with_theme(&ColorfulTheme::default())
            .with_prompt("Enter new key")
            .with_confirmation("Retype key", "keys do not match")
            .interact()?;

        let salt: [u8; 16] = rand::random();

        let mut derived_key = [0u8; 32];
        Argon2::default().hash_password_into(user_key.as_bytes(), &salt, &mut derived_key)?;

        let key_aes = Aes256Gcm::new(&derived_key.into());

        let key: [u8; 32] = rand::random();
        let nonce_slice: [u8; 12] = rand::random();
        let nonce = Nonce::from_slice(&nonce_slice);

        let encrypted_key = key_aes.encrypt(nonce, &key[..])?;

        let global_config = Config::open_default()?;

        let name = Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Enter username")
            .default(
                global_config
                    .get_string("user.name")
                    .unwrap_or(whoami::realname()),
            )
            .interact()?;

        let email = if let Ok(email) = global_config.get_string("user.email") {
            Input::with_theme(&ColorfulTheme::default())
                .with_prompt("Enter email")
                .default(email)
                .validate_with(|inp: &String| validate_email(inp))
                .interact()?
        } else {
            Input::with_theme(&ColorfulTheme::default())
                .with_prompt("Enter email")
                .validate_with(|inp: &String| validate_email(inp))
                .interact()?
        };

        let remote = if Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Do you want to enter a remote service")
            .interact()?
        {
            let url = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("Enter remote url")
                .validate_with(|inp: &String| validate_url(inp))
                .interact()?;

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
        let store_aes = Aes256Gcm::new(&key.into());

        let user_nonce: [u8; 12] = rand::random();

        user.save(&data_dir.join(USER_BIN_PATH), &store_aes, user_nonce)?;
        store.save(&data_dir.join(STORE_BIN_PATH))?;

        let mut init_opts = RepositoryInitOptions::new();
        init_opts.initial_head("main");

        let repo = Repository::init_opts(&data_dir, &init_opts)?;

        repo.add_ignore_rule(&format!("{STORE_BIN_PATH}.bak\n{USER_BIN_PATH}.bak"))?;

        if let Some(remote) = &user.remote {
            repo.remote("origin", remote)?;
        }

        let mut index = repo.index()?;

        index.add_path(Path::new(STORE_BIN_PATH))?;
        index.add_path(Path::new(USER_BIN_PATH))?;

        let oid = index.write_tree()?;
        let signature = Signature::now(&user.name, &user.email)?;

        repo.commit(
            Some("HEAD"),
            &signature,
            &signature,
            "Initialize store",
            &repo.find_tree(oid)?,
            &[],
        )?;

        Ok(Self {
            store,
            store_aes,
            data_dir,
            key_aes,
            repo,
            user,
            user_nonce,
            store_dirty: false,
            user_dirty: false,
        })
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
    ) -> Result<()> {
        let password = if input {
            Password::with_theme(&ColorfulTheme::default())
                .with_prompt("Enter your password")
                .validate_with(|inp: &String| length_validator(inp))
                .interact()?
        } else {
            let password_charset = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
            let mut rng = rand::thread_rng();

            let subset = &password_charset[..(if special_chars { 94 } else { 62 })];
            let password = subset.choose_multiple(&mut rng, len).copied().collect();

            String::from_utf8(password)?
        };

        let nonce_slice: [u8; 12] = rand::random();
        let nonce = Nonce::from_slice(&nonce_slice);

        let ciphertext = self
            .store_aes
            .encrypt(nonce, password.as_bytes().as_ref())?;

        match self.store.items.entry(label.to_string()) {
            Entry::Vacant(entry) => {
                entry.insert(Item::new(nonce_slice, ciphertext));
            }

            Entry::Occupied(mut entry) => {
                let confirmed = overwrite
                    || Confirm::with_theme(&ColorfulTheme::default())
                        .with_prompt("Do you want to modify?")
                        .interact()?;
                if confirmed {
                    entry.insert(Item::new(nonce_slice, ciphertext));
                }
            }
        };

        self.store_dirty = true;

        Ok(())
    }

    pub fn delete(&mut self, label: &str) {
        if self.store.items.remove(label).is_none() {
            println!("{}", "No item found in store".bright_red());
        }

        self.store_dirty = true;
    }

    pub fn copy(&self, label: &str) -> Result<()> {
        let Some(item) = self.store.items.get(label) else {
            println!("No item found in store");
            return Ok(());
        };

        let Item {
            nonce, password, ..
        } = &item;

        let plaintext = self.store_aes.decrypt(nonce.into(), password.as_slice())?;

        let mut clipboard: ClipboardContext = ClipboardProvider::new()?;

        clipboard.set_contents(String::from_utf8(plaintext)?)?;

        Ok(())
    }

    pub fn list(&self) -> Result<()> {
        if self.store.is_empty() {
            println!("Empty store");
            return Ok(());
        }

        let mut t = Table::new(["Labels".to_owned(), "Passwords".to_owned()]);

        for (label, item) in &self.store.items {
            let Item { nonce, password } = &item;

            let nonce = Nonce::from_slice(nonce);
            let plaintext = self.store_aes.decrypt(nonce, password.as_slice())?;

            t.insert([label.to_owned(), String::from_utf8(plaintext)?]);
        }

        t.display()?;

        Ok(())
    }

    pub fn history(&self) -> Result<()> {
        let mut revwalk = self.repo.revwalk()?;
        revwalk.push_head()?;

        for commit in revwalk {
            let commit = self.repo.find_commit(commit?)?;
            println!("{}", commit.message().context(InvalidCommitMessageErr {})?);
        }

        Ok(())
    }
}

impl Manager {
    pub fn save(&self, message: &str) -> Result<()> {
        if !(self.store_dirty || self.user_dirty) {
            return Ok(());
        }

        let mut index = self.repo.index()?;

        if self.store_dirty {
            self.store.save(&self.data_dir.join(STORE_BIN_PATH))?;
            index.add_path(Path::new(STORE_BIN_PATH))?;
        }

        if self.user_dirty {
            self.user.save(
                &self.data_dir.join(USER_BIN_PATH),
                &self.store_aes,
                self.user_nonce,
            )?;
            index.add_path(Path::new(USER_BIN_PATH))?;
        }

        let oid = index.write_tree()?;
        let signature = Signature::now(&self.user.name, &self.user.email)?;
        let parent_commit = self
            .repo
            .head()?
            .resolve()?
            .peel(ObjectType::Commit)?
            .into_commit()
            .map_err(|_| git2::Error::from_str("Couldn't find commit"))?;

        let tree = self.repo.find_tree(oid)?;
        self.repo.commit(
            Some("HEAD"),
            &signature,
            &signature,
            message,
            &tree,
            &[&parent_commit],
        )?;

        Ok(())
    }
}

use std::{
    path::{Path, PathBuf},
    str::FromStr,
};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::Argon2;
use chrono::{FixedOffset, NaiveDateTime};
use clipboard::{ClipboardContext, ClipboardProvider};
use dialoguer::{theme::ColorfulTheme, Confirm, Input, Password};
use email_address::EmailAddress;
use git2::{
    Config, Cred, Direction, Oid, Remote, RemoteCallbacks, Repository, RepositoryInitOptions,
    Signature,
};
use hashbrown::hash_map::Entry;
use owo_colors::OwoColorize;
use rand::seq::SliceRandom;
use snafu::{OptionExt, ResultExt};
use url::Url;

use crate::{
    error::{
        ChronoErr, CommitMsgFormatErr, FsErr, HostErr, InvalidCommitMessageUtf8Err,
        InvalidShortIdErr, PassManagerErr, PreviousVersionErr, Result,
    },
    store::{Item, Store},
    table::Table,
    user::{get_remote_credentials, User},
};

pub const ORIGIN: &str = "origin";

pub struct Manager {
    pub repo: Repository,
    pub data_dir: PathBuf,

    pub key_aes: Aes256Gcm,
    pub store_aes: Aes256Gcm,

    pub store: Store,
    pub user: User,
    pub user_nonce: [u8; 12],

    pub fs_dirty: bool,

    pub success_message: Option<String>,
}

pub fn length_validator(inp: &str) -> Result<(), String> {
    (inp.len() >= 8)
        .then_some(())
        .ok_or_else(|| "Password must be longer than 8".to_string())
}

pub const STORE_BIN_PATH: &str = "pm_store.bin";
pub const USER_BIN_PATH: &str = "user.bin";

impl Manager {
    pub fn new(data_dir: PathBuf) -> Result<Self> {
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

            fs_dirty: false,
            success_message: None,
        })
    }

    pub fn init(data_dir: PathBuf) -> Result<Self> {
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
                    .unwrap_or_else(|_| whoami::realname()),
            )
            .interact()?;

        let colorful_theme = ColorfulTheme::default();
        let mut email_input = Input::with_theme(&colorful_theme).with_prompt("Enter email");

        if let Ok(email) = global_config.get_string("user.email") {
            email_input = email_input.default(email);
        };

        let email = email_input
            .validate_with(|inp: &String| {
                EmailAddress::from_str(inp)
                    .map(|_| ())
                    .map_err(|err| err.to_string())
            })
            .interact()?;

        let mut user = User::new(name, email);

        let store = Store::new(encrypted_key, salt, nonce_slice);
        let store_aes = Aes256Gcm::new(&key.into());

        let user_nonce: [u8; 12] = rand::random();

        std::fs::create_dir(&data_dir).context(FsErr {
            path: data_dir.display().to_string(),
        })?;
        user.save(&data_dir.join(USER_BIN_PATH), &store_aes, user_nonce)?;
        store.save(&data_dir.join(STORE_BIN_PATH))?;

        let mut remote_has_data = false;

        let repo = if Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Do you want to enter a remote service")
            .interact()?
        {
            let remote_url = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("Enter remote url")
                .validate_with(|inp: &String| {
                    (|| {
                        let url = Url::parse(inp)?;
                        let (username, password) =
                            get_remote_credentials(&url.host().context(HostErr)?.to_string())?;

                        let mut cb = RemoteCallbacks::new();
                        cb.credentials(|_, _, _| Cred::userpass_plaintext(&username, &password));

                        let mut remote = Remote::create_detached(inp.as_bytes())?;

                        remote.connect_auth(Direction::Fetch, Some(cb), None)?;

                        remote_has_data = !remote.list()?.is_empty();

                        Ok::<(), PassManagerErr>(())
                    })()
                    .map_err(|err| err.to_string())
                })
                .interact()?;

            let needs_creds = Confirm::with_theme(&ColorfulTheme::default())
                .with_prompt("Does remote needs credentials")
                .interact()?;

            user.set_remote(&remote_url, Some(needs_creds))?;

            let repo = if remote_has_data
                && Confirm::with_theme(&ColorfulTheme::default())
                    .with_prompt("Remote has previous data. Do you want to use it")
                    .interact()?
            {
                Repository::clone(&remote_url, &data_dir)?
            } else {
                let mut init_opts = RepositoryInitOptions::new();
                init_opts.initial_head("main");

                Repository::init_opts(&data_dir, &init_opts)?
            };

            set_repo(&repo, &user)?;
            repo.remote(ORIGIN, &remote_url)?;

            repo
        } else {
            let mut init_opts = RepositoryInitOptions::new();
            init_opts.initial_head("main");

            let repo = Repository::init_opts(&data_dir, &init_opts)?;

            set_repo(&repo, &user)?;

            repo
        };

        Ok(Self {
            store,
            store_aes,
            data_dir,
            key_aes,
            repo,
            user,
            user_nonce,

            fs_dirty: false,
            success_message: None,
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
        let aes_nonce = Nonce::from_slice(&nonce_slice);

        let ciphertext = self
            .store_aes
            .encrypt(aes_nonce, password.as_bytes().as_ref())?;

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

        self.fs_dirty = true;
        self.success_message = Some(format!("Successfully added '{label}' to store"));

        Ok(())
    }

    pub fn delete(&mut self, label: &str) {
        if self.store.items.remove(label).is_none() {
            println!("{}", "No item found in store".bright_red());
        }

        self.fs_dirty = true;
        self.success_message = Some(format!("Successfully deleted '{label}' from store"));
    }

    pub fn copy(&mut self, label: &str) -> Result<()> {
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

        self.success_message = Some(format!("Successfully copied '{label}' to clipboard"));

        Ok(())
    }

    pub fn list(&self) -> Result<()> {
        if self.store.is_empty() {
            println!("Empty store");
            return Ok(());
        }

        let mut table = Table::new(["Labels".to_owned(), "Passwords".to_owned()]);

        for (label, item) in &self.store.items {
            let Item { nonce, password } = &item;

            let nonce = Nonce::from_slice(nonce);
            let plaintext = self.store_aes.decrypt(nonce, password.as_slice())?;

            table.insert([label.to_owned(), String::from_utf8(plaintext)?]);
        }

        table.display()?;

        Ok(())
    }

    pub fn history(&self) -> Result<()> {
        let mut revwalk = self.repo.revwalk()?;
        revwalk.push_head()?;

        let mut table = Table::new([
            "Binary".to_string(),
            "Action".to_string(),
            "Value".to_string(),
            "Time".to_string(),
            "Id".to_string(),
        ]);

        for oid in revwalk {
            let commit = self.repo.find_commit(oid?)?;

            let commit_message = commit.message().context(InvalidCommitMessageUtf8Err)?;
            let commit_parts = parse_commit_message(commit_message);

            let commit_time = commit.time();
            let time = NaiveDateTime::from_timestamp_opt(commit_time.seconds(), 0)
                .context(ChronoErr { item: "time" })?;
            let tz = FixedOffset::east_opt(commit_time.offset_minutes() * 60)
                .context(ChronoErr { item: "offset" })?;
            let time = time + tz;

            table.insert([
                commit_parts[0].clone(),
                commit_parts[1].clone(),
                commit_parts[2].clone(),
                time.format("%e %b %y %H:%M").to_string(),
                commit
                    .into_object()
                    .short_id()?
                    .as_str()
                    .context(InvalidShortIdErr)?
                    .to_string(),
            ]);
        }

        table.display()?;

        Ok(())
    }

    pub fn undo(&mut self, id: &Option<String>) -> Result<()> {
        let commit = id.as_ref().map_or_else(
            || {
                self.repo
                    .head()?
                    .resolve()?
                    .peel_to_commit()
                    .map_err(|_| git2::Error::from_str("Couldn't find commit"))
            },
            |id| self.repo.find_commit(Oid::from_str(id)?),
        )?;

        let message = commit
            .message()
            .context(InvalidCommitMessageUtf8Err)?
            .to_string();
        let parts = parse_commit_message(&message);

        drop(commit);

        match parts[0].as_str() {
            "store" => match parts[1].as_str() {
                "add" => self.delete(&parts[2]),
                action @ ("delete" | "reset") => {
                    let parent_commit = id
                        .as_ref()
                        .map_or_else(
                            || {
                                self.repo
                                    .head()?
                                    .resolve()?
                                    .peel_to_commit()
                                    .map_err(|_| git2::Error::from_str("Couldn't find commit"))
                            },
                            |id| self.repo.find_commit(Oid::from_str(id)?),
                        )?
                        .parent(0)?;

                    let tree = parent_commit.tree()?;
                    let blob = tree
                        .get_name(STORE_BIN_PATH)
                        .context(PreviousVersionErr {
                            bin: STORE_BIN_PATH,
                        })?
                        .to_object(&self.repo)?
                        .into_blob()
                        .map_err(|_| git2::Error::from_str("Couldn't convert object to blob"))?;

                    let old_store =
                        rkyv::from_bytes::<Store>(blob.content()).map_err(|err| err.to_string())?;

                    if action == "delete" {
                        self.store
                            .items
                            .insert(parts[2].clone(), old_store.items[&parts[2]].clone());
                    } else if action == "reset" {
                        self.store.items = old_store.items;
                    }
                }

                "modify" => {
                    println!("{}", "Cannot undo password modication".bright_red());
                }
                _ => return Err(CommitMsgFormatErr { message }.build()),
            },

            "user" => match parts[1].as_str() {
                "set" => {
                    let parent_commit = id
                        .as_ref()
                        .map_or_else(
                            || {
                                self.repo
                                    .head()?
                                    .resolve()?
                                    .peel_to_commit()
                                    .map_err(|_| git2::Error::from_str("Couldn't find commit"))
                            },
                            |id| self.repo.find_commit(Oid::from_str(id)?),
                        )?
                        .parent(0)?;

                    let tree = parent_commit.tree()?;
                    let blob = tree
                        .get_name(USER_BIN_PATH)
                        .context(PreviousVersionErr { bin: USER_BIN_PATH })?
                        .to_object(&self.repo)?
                        .into_blob()
                        .map_err(|_| git2::Error::from_str("Couldn't convert object to blob"))?;

                    let (nonce_slice, ciphertext) = blob.content().split_at(12);
                    let decrypted_buf = self.store_aes.decrypt(nonce_slice.into(), ciphertext)?;

                    let old_user =
                        rkyv::from_bytes::<User>(&decrypted_buf).map_err(|err| err.to_string())?;

                    let fields = parts[2].split(',').collect::<Vec<_>>();

                    for field in fields {
                        if field == "name" {
                            self.user.name = old_user.name.clone();
                        } else if field == "email" {
                            self.user.email = old_user.email.clone();
                        } else if field == "remote" {
                            self.user.remote = old_user.remote.clone();
                        }
                    }
                }
                _ => return Err(CommitMsgFormatErr { message }.build()),
            },

            _ => return Err(CommitMsgFormatErr { message }.build()),
        }

        Ok(())
    }
}

impl Manager {
    pub fn save(self, message: &str) -> Result<Option<String>> {
        if self.fs_dirty {
            let mut index = self.repo.index()?;

            self.store.save(&self.data_dir.join(STORE_BIN_PATH))?;
            self.user.save(
                &self.data_dir.join(USER_BIN_PATH),
                &self.store_aes,
                self.user_nonce,
            )?;

            index.add_path(Path::new(STORE_BIN_PATH))?;
            index.add_path(Path::new(USER_BIN_PATH))?;

            let oid = index.write_tree()?;
            let signature = Signature::now(&self.user.name, &self.user.email)?;
            let parent_commit = self
                .repo
                .head()?
                .resolve()?
                .peel_to_commit()
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
        }

        Ok(self.success_message)
    }
}

fn parse_commit_message(message: &str) -> Vec<String> {
    let mut commit_parts = message.split(' ').map(String::from).collect::<Vec<_>>();

    if commit_parts.len() == 2 {
        commit_parts.push("-".to_string());
    }

    commit_parts
}

fn set_repo(repo: &Repository, user: &User) -> Result<()> {
    repo.add_ignore_rule(&format!("{STORE_BIN_PATH}.bak\n{USER_BIN_PATH}.bak"))?;

    let mut index = repo.index()?;

    index.add_path(Path::new(STORE_BIN_PATH))?;
    index.add_path(Path::new(USER_BIN_PATH))?;

    let oid = index.write_tree()?;
    let signature = Signature::now(&user.name, &user.email)?;

    repo.commit(
        Some("HEAD"),
        &signature,
        &signature,
        "store initialize",
        &repo.find_tree(oid)?,
        &[],
    )?;
    Ok(())
}

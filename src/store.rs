use std::{
    fs::File,
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
use git2::{Cred, Direction, FetchOptions, PushOptions, RemoteCallbacks};
use hashbrown::HashMap;
use snafu::{OptionExt, ResultExt};

use crate::{
    cmd::SyncDirection,
    error::{CommandErr, FsErr, Result, SplitErr},
    manager::{length_validator, Manager},
};

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

    pub fn open(path: &PathBuf) -> Result<Self> {
        let buf = std::fs::read(path).context(FsErr {
            path: path.display().to_string(),
        })?;
        let bin = rkyv::from_bytes::<Self>(&buf).map_err(|err| err.to_string())?;

        Ok(bin)
    }

    pub fn save(&self, path: &PathBuf) -> Result<()> {
        let data = rkyv::to_bytes::<_, 1024>(self).map_err(|err| err.to_string())?;
        std::fs::write(path, &data).context(FsErr {
            path: path.display().to_string(),
        })?;

        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn delete(&mut self, label: &str) -> bool {
        self.items.remove(label).is_some()
    }
}

impl Manager {
    pub fn reset(&mut self) -> Result<()> {
        if Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Do you want to reset?")
            .interact()?
        {
            self.store.items = HashMap::new();
        }

        self.fs_dirty = true;
        self.success_message = Some("Successfully reset store".to_string());

        Ok(())
    }

    pub fn modify(&mut self) -> Result<()> {
        let new_key = Password::with_theme(&ColorfulTheme::default())
            .with_prompt("Enter new key")
            .with_confirmation("Retype new key", "keys do not match")
            .validate_with(|inp: &String| length_validator(inp))
            .interact()?;

        let enc_key = self
            .key_aes
            .decrypt(&self.store.nonce.into(), self.store.key.as_slice())?;

        let new_salt: [u8; 16] = rand::random();
        let new_nonce: [u8; 12] = rand::random();

        self.store.nonce = new_nonce;
        self.store.salt = new_salt;

        let mut new_cipher_key: [u8; 32] = [0; 32];
        Argon2::default().hash_password_into(new_key.as_bytes(), &new_salt, &mut new_cipher_key)?;

        let new_key_cipher = Aes256Gcm::new(&new_cipher_key.into());

        let new_key = new_key_cipher.encrypt(&new_nonce.into(), enc_key.as_slice())?;

        self.store.key = new_key;

        self.fs_dirty = true;
        self.success_message = Some("Successfully modified store key".to_string());

        Ok(())
    }

    pub fn sync(&mut self, dir: SyncDirection) -> Result<()> {
        let Some(user_remote) = &self.user.remote else {
            println!("Remote not set");
            return Ok(());
        };

        match dir {
            SyncDirection::Push => {
                let mut remote = self.repo.find_remote("origin")?;

                let mut push_options = PushOptions::new();

                let mut push_callbacks = RemoteCallbacks::new();
                push_callbacks.credentials(|_, _, _| {
                    let cred = get_remote_credentials(&user_remote.host)
                        .map_err(|_| git2::Error::from_str("Couldn't get credentials"))?;
                    Cred::userpass_plaintext(&cred["username"], &cred["password"])
                });

                let mut conn_callbacks = RemoteCallbacks::new();
                conn_callbacks.credentials(|_, _, _| {
                    let cred = get_remote_credentials(&user_remote.host)
                        .map_err(|_| git2::Error::from_str("Couldn't get credentials"))?;
                    Cred::userpass_plaintext(&cred["username"], &cred["password"])
                });

                remote.connect_auth(Direction::Push, Some(conn_callbacks), None)?;

                push_options.remote_callbacks(push_callbacks);

                remote.push(
                    &["refs/heads/main:refs/heads/main"],
                    Some(&mut push_options),
                )?;

                self.success_message = Some("Successfully pushed store to remote".to_string());
            }

            SyncDirection::Pull => {
                let mut remote = self.repo.find_remote("origin")?;

                let mut callbacks = RemoteCallbacks::new();
                callbacks.credentials(|_, _, _| {
                    let cred = get_remote_credentials(&user_remote.host)
                        .map_err(|_| git2::Error::from_str("Couldn't get credentials"))?;
                    Cred::userpass_plaintext(&cred["username"], &cred["password"])
                });

                let mut fetch_options = FetchOptions::new();
                fetch_options.remote_callbacks(callbacks);

                remote.fetch(&["main"], Some(&mut fetch_options), None)?;

                let fetch_head = self.repo.find_reference("FETCH_HEAD")?;
                let fetch_commit = self.repo.reference_to_annotated_commit(&fetch_head)?;

                let (analysis, _) = self.repo.merge_analysis(&[&fetch_commit])?;

                if analysis.is_fast_forward() {
                    match self.repo.find_reference("refs/heads/main") {
                        Ok(mut r) => {
                            let name = match r.name() {
                                Some(s) => s.to_string(),
                                None => String::from_utf8_lossy(r.name_bytes()).to_string(),
                            };

                            r.set_target(
                                fetch_commit.id(),
                                &format!(
                                    "Fast-Forward: Setting {} to id: {}",
                                    name,
                                    fetch_commit.id()
                                ),
                            )?;

                            self.repo.set_head(&name)?;
                            self.repo.checkout_head(Some(
                                git2::build::CheckoutBuilder::default().force(),
                            ))?;
                        }
                        Err(_) => {
                            self.repo.reference(
                                "refs/heads/main",
                                fetch_commit.id(),
                                true,
                                &format!("Setting main to {}", fetch_commit.id()),
                            )?;

                            self.repo.set_head("refs/heads/main")?;
                            self.repo.checkout_head(Some(
                                git2::build::CheckoutBuilder::default()
                                    .allow_conflicts(true)
                                    .conflict_style_merge(true)
                                    .force(),
                            ))?;
                        }
                    };
                } else if analysis.is_normal() {
                    let head_commit = self
                        .repo
                        .reference_to_annotated_commit(&self.repo.head()?)?;

                    let local_tree = self.repo.find_commit(head_commit.id())?.tree()?;
                    let remote_tree = self.repo.find_commit(fetch_commit.id())?.tree()?;

                    let ancestor = self
                        .repo
                        .find_commit(self.repo.merge_base(head_commit.id(), fetch_commit.id())?)?
                        .tree()?;

                    let mut idx =
                        self.repo
                            .merge_trees(&ancestor, &local_tree, &remote_tree, None)?;

                    if idx.has_conflicts() {
                        self.repo.checkout_index(Some(&mut idx), None)?;
                        return Ok(());
                    }

                    let result_tree = self.repo.find_tree(idx.write_tree_to(&self.repo)?)?;

                    let msg = format!("Merge: {} into {}", fetch_commit.id(), head_commit.id());
                    let sig = self.repo.signature()?;

                    let local_commit = self.repo.find_commit(head_commit.id())?;
                    let remote_commit = self.repo.find_commit(fetch_commit.id())?;

                    self.repo.commit(
                        Some("HEAD"),
                        &sig,
                        &sig,
                        &msg,
                        &result_tree,
                        &[&local_commit, &remote_commit],
                    )?;

                    self.repo.checkout_head(None)?;
                }

                self.success_message = Some("Successfully pulled store from remote".to_string());
            }
        }

        Ok(())
    }

    pub fn nuke(&mut self, sync: bool, archive: bool) -> Result<()> {
        if sync {
            self.sync(SyncDirection::Push)?;
        }

        if archive {
            let archive_file = File::create("pm.tar").context(FsErr {
                path: "pm.tar".to_string(),
            })?;

            let mut builder = tar::Builder::new(archive_file);
            builder.append_dir_all("PassManager", &self.data_dir)?;

            builder.finish()?;
        }

        std::fs::remove_dir_all(&self.data_dir).context(FsErr {
            path: self.data_dir.display().to_string(),
        })?;

        self.success_message = Some("Successfully nuked the data".to_string());
        Ok(())
    }
}

fn get_remote_credentials(host: &str) -> Result<HashMap<String, String>> {
    let command = Command::new("git")
        .args(["credential", "fill"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;

    command
        .stdin
        .context(CommandErr {
            fd: "stdin".to_string(),
        })?
        .write_all(format!("protocol=https\nhost={host}").as_bytes())?;

    let mut s = String::new();
    command
        .stdout
        .context(CommandErr {
            fd: "stdin".to_string(),
        })?
        .read_to_string(&mut s)?;

    let mut config = HashMap::new();

    for line in s.split_terminator('\n') {
        let (k, v) = line.split_once('=').context(SplitErr {})?;
        config.insert(k.into(), v.into());
    }

    Ok(config)
}

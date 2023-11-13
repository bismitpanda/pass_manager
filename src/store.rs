use std::{fs::File, path::PathBuf};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm,
};
use argon2::Argon2;
use dialoguer::{theme::ColorfulTheme, Confirm, Password};
use git2::{Cred, Direction, FetchOptions, PushOptions, RemoteCallbacks};
use hashbrown::HashMap;
use snafu::ResultExt;

use crate::{
    cmd::SyncDirection,
    error::{FsErr, Result},
    manager::{length_validator, Manager},
};

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone)]
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

        let mut remote = self.repo.find_remote("origin")?;
        let mut cb = RemoteCallbacks::new();
        cb.credentials(|_, _, _| {
            Cred::userpass_plaintext(&user_remote.username, &user_remote.password)
        });

        cb.transfer_progress(|progress| true);

        match dir {
            SyncDirection::Push => {
                remote.connect_auth(Direction::Push, Some(cb), None)?;

                let mut push_options = PushOptions::new();
                let mut push_cb = RemoteCallbacks::new();
                push_cb.credentials(|_, _, _| {
                    Cred::userpass_plaintext(&user_remote.username, &user_remote.password)
                });
                push_options.remote_callbacks(push_cb);

                remote.push(
                    &["refs/heads/main:refs/heads/main"],
                    Some(&mut push_options),
                )?;

                self.success_message = Some("Successfully pushed store to remote".to_string());
            }

            SyncDirection::Pull => {
                let mut fetch_options = FetchOptions::new();
                fetch_options.remote_callbacks(cb);

                remote.fetch(&["main"], Some(&mut fetch_options), None)?;

                let fetch_head = self.repo.find_reference("FETCH_HEAD")?;
                let fetch_commit = self.repo.reference_to_annotated_commit(&fetch_head)?;

                let (analysis, _) = self.repo.merge_analysis(&[&fetch_commit])?;

                if analysis.is_fast_forward() {
                    if let Ok(mut r) = self.repo.find_reference("refs/heads/main") {
                        let name = r.name().map_or_else(
                            || String::from_utf8_lossy(r.name_bytes()).to_string(),
                            ToString::to_string,
                        );

                        r.set_target(
                            fetch_commit.id(),
                            &format!(
                                "Fast-Forward: Setting {} to id: {}",
                                name,
                                fetch_commit.id()
                            ),
                        )?;

                        self.repo.set_head(&name)?;
                        self.repo
                            .checkout_head(Some(git2::build::CheckoutBuilder::default().force()))?;
                    } else {
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
                    };
                } else if analysis.is_normal() {
                    let head_commit = self
                        .repo
                        .reference_to_annotated_commit(&self.repo.head()?)?;

                    let ancestor = self
                        .repo
                        .find_commit(self.repo.merge_base(head_commit.id(), fetch_commit.id())?)?
                        .tree()?;

                    let mut index = self.repo.merge_trees(
                        &ancestor,
                        &self.repo.find_commit(head_commit.id())?.tree()?,
                        &self.repo.find_commit(fetch_commit.id())?.tree()?,
                        None,
                    )?;

                    if index.has_conflicts() {
                        return Ok(self.repo.checkout_index(Some(&mut index), None)?);
                    }

                    let sig = self.repo.signature()?;

                    self.repo.commit(
                        Some("HEAD"),
                        &sig,
                        &sig,
                        &format!("store pull {}:{}", fetch_commit.id(), head_commit.id()),
                        &self.repo.find_tree(index.write_tree_to(&self.repo)?)?,
                        &[
                            &self.repo.find_commit(head_commit.id())?,
                            &self.repo.find_commit(fetch_commit.id())?,
                        ],
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

use std::{fs::File, path::PathBuf};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm,
};
use argon2::Argon2;
use dialoguer::{theme::ColorfulTheme, Confirm, MultiSelect, Password};
use git2::{Cred, Direction, PushOptions, RemoteCallbacks, Repository};
use hashbrown::HashMap;
use snafu::ResultExt;

use crate::{
    cmd::SyncDirection,
    diff,
    error::{FsErr, Result},
    manager::{length_validator, Manager, ORIGIN, STORE_BIN_PATH},
    user::Credentials,
};
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone, PartialEq, Eq)]
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

    pub fn sync(&mut self, dir: SyncDirection, force: bool) -> Result<()> {
        let Some(user_remote) = &self.user.remote else {
            return Ok(println!("Remote not set"));
        };

        let mut remote = self.repo.find_remote(ORIGIN)?;
        let mut cb = RemoteCallbacks::new();
        if let Some(Credentials { username, password }) = &user_remote.creds {
            cb.credentials(|_, _, _| Cred::userpass_plaintext(username, password));
        }

        match dir {
            SyncDirection::Push => {
                remote.connect_auth(Direction::Push, Some(cb), None)?;

                let mut push_options = PushOptions::new();
                let mut push_cb = RemoteCallbacks::new();
                if let Some(Credentials { username, password }) = &user_remote.creds {
                    push_cb.credentials(|_, _, _| Cred::userpass_plaintext(username, password));
                }
                push_options.remote_callbacks(push_cb);

                remote.push(
                    &[if force {
                        "+refs/heads/main:refs/heads/main"
                    } else {
                        "refs/heads/main:refs/heads/main"
                    }],
                    Some(&mut push_options),
                )?;

                self.success_message = Some("Successfully pushed store to remote".to_string());
            }

            SyncDirection::Pull => {
                let temp_clone_dir = std::env::temp_dir().join("pm_remote");
                std::fs::create_dir_all(&temp_clone_dir).context(FsErr {
                    path: temp_clone_dir.display().to_string(),
                })?;

                Repository::clone(&user_remote.url, &temp_clone_dir)?;

                let store = rkyv::from_bytes::<Store>(
                    &std::fs::read(temp_clone_dir.join(STORE_BIN_PATH)).context(FsErr {
                        path: temp_clone_dir.join(STORE_BIN_PATH).display().to_string(),
                    })?,
                )
                .map_err(|err| err.to_string())?;

                let store_diff_items = diff::diff(&self.store.items, &store.items).concat();
                let store_diff_indices = MultiSelect::with_theme(&ColorfulTheme::default())
                    .with_prompt("Select changes to pull for store")
                    .items(&store_diff_items)
                    .interact()?;

                let selected_store_items =
                    get_values_from_indices(&store_diff_indices, &store_diff_items);

                for diff::Item(diff_kind, key) in selected_store_items {
                    match diff_kind {
                        diff::Kind::Added | diff::Kind::Modified => {
                            let value = store.items[&key].clone();
                            self.store.items.insert(key, value);
                        }

                        diff::Kind::Deleted => {
                            self.store.items.remove(&key);
                        }
                    }
                }

                std::fs::remove_dir_all(&temp_clone_dir).context(FsErr {
                    path: temp_clone_dir.display().to_string(),
                })?;

                self.success_message = Some("Successfully pulled store from remote".to_string());
                todo!();
            }
        }

        Ok(())
    }

    pub fn nuke(&mut self, sync: bool, archive: bool) -> Result<()> {
        if sync {
            self.sync(SyncDirection::Push, true)?;
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

fn get_values_from_indices<T: Clone>(indices: &[usize], values: &[T]) -> Vec<T> {
    indices
        .iter()
        .map(|&i| values[i].clone())
        .collect::<Vec<_>>()
}

use std::path::PathBuf;

use aes_gcm::{aead::Aead, Aes256Gcm};
use owo_colors::OwoColorize;
use snafu::{OptionExt, ResultExt};
use url::Url;

use crate::{
    error::{FsErr, HostErr, Result},
    manager::Manager,
};

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone)]
#[archive(check_bytes)]
pub struct Remote {
    pub host: String,
    pub url: String,
}

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[archive(check_bytes)]
pub struct User {
    pub name: String,
    pub email: String,
    pub remote: Option<Remote>,
}

impl User {
    pub fn open(path: &PathBuf, cipher: &Aes256Gcm) -> Result<([u8; 12], Self)> {
        let buf = std::fs::read(path).context(FsErr {
            path: path.display().to_string(),
        })?;
        let (nonce_slice, ciphertext) = buf.split_at(12);
        let decrypted_buf = cipher.decrypt(nonce_slice.into(), ciphertext)?;

        let nonce: [u8; 12] = nonce_slice.try_into()?;

        Ok((
            nonce,
            rkyv::from_bytes::<Self>(&decrypted_buf).map_err(|err| err.to_string())?,
        ))
    }

    pub fn save(&self, path: &PathBuf, cipher: &Aes256Gcm, nonce: [u8; 12]) -> Result<()> {
        let data = rkyv::to_bytes::<_, 1024>(self).map_err(|err| err.to_string())?;
        let encrypted_data = cipher.encrypt(&nonce.into(), data.as_slice())?;
        std::fs::write(path, [nonce.to_vec(), encrypted_data].concat()).context(FsErr {
            path: path.display().to_string(),
        })?;

        Ok(())
    }
}

impl Manager {
    pub fn get_user(&self) {
        println!(
            "{}: {}
{}: {}
{}: {}",
            "Name".bright_yellow(),
            self.user.name.bright_cyan(),
            "Email".bright_yellow(),
            self.user.email.bright_cyan(),
            "Remote".bright_yellow(),
            self.user
                .remote
                .clone()
                .map_or_else(|| "Not set".to_string(), |remote| remote.url)
                .bright_cyan()
        );
    }

    pub fn set_user(
        &mut self,
        name: &Option<String>,
        email: &Option<String>,
        remote: &Option<String>,
    ) -> Result<()> {
        if let Some(name) = name {
            self.user.name = name.clone();
        }

        if let Some(email) = email {
            self.user.email = email.clone();
        }

        if let Some(remote) = remote {
            if remote == "-" {
                if self.repo.find_remote("origin").is_ok() {
                    self.repo.remote_delete("origin")?;
                }

                self.user.remote = None;
            } else {
                if self.repo.find_remote("origin").is_ok() {
                    self.repo.remote_set_url("origin", remote)?;
                } else {
                    self.repo.remote("origin", remote)?;
                }

                let url = Url::parse(remote)?;

                self.user.remote = Some(Remote {
                    host: url.host().context(HostErr {})?.to_string(),
                    url: remote.clone(),
                });
            }
        }

        self.fs_dirty = true;

        Ok(())
    }
}

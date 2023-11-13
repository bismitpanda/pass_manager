use std::{
    io::prelude::*,
    path::PathBuf,
    process::{Command, Stdio},
};

use aes_gcm::{aead::Aead, Aes256Gcm};
use owo_colors::OwoColorize;
use snafu::{OptionExt, ResultExt};
use url::Url;

use crate::{
    error::{CommandErr, CredsErr, FsErr, HostErr, Result, SplitErr},
    manager::Manager,
};

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone)]
#[archive(check_bytes)]
pub struct Remote {
    pub host: String,
    pub url: String,
    pub username: String,
    pub password: String,
}

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone)]
#[archive(check_bytes)]
pub struct User {
    pub name: String,
    pub email: String,
    pub remote: Option<Remote>,
}

impl User {
    pub const fn new(name: String, email: String) -> Self {
        Self {
            name,
            email,
            remote: None,
        }
    }

    pub fn set_remote(&mut self, remote: &str) -> Result<()> {
        if remote == "-" {
            self.remote = None;
        } else {
            let url = Url::parse(remote)?;

            let host = url.host().context(HostErr)?.to_string();
            let (username, password) = get_remote_credentials(&host).map_err(|err| {
                git2::Error::from_str(&format!("Couldn't get credentials: {err}"))
            })?;

            self.remote = Some(Remote {
                host,
                url: remote.to_string(),
                username,
                password,
            });
        }

        Ok(())
    }

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
            } else if self.repo.find_remote("origin").is_ok() {
                self.repo.remote_set_url("origin", remote)?;
            } else {
                self.repo.remote("origin", remote)?;
            }

            self.user.set_remote(remote)?;
        }

        let fields = [("name", name), ("email", email), ("remote", remote)]
            .iter()
            .filter_map(|(name, el)| el.is_some().then_some(*name))
            .collect::<Vec<_>>()
            .join(", ");

        self.fs_dirty = true;
        self.success_message = Some(format!("Successfully set user {fields}"));

        Ok(())
    }
}

fn get_remote_credentials(host: &str) -> Result<(String, String)> {
    let command = Command::new("git")
        .args(["credential", "fill"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;

    command
        .stdin
        .context(CommandErr { fd: "stdin" })?
        .write_all(format!("protocol=https\nhost={host}").as_bytes())?;

    let mut s = String::new();
    command
        .stdout
        .context(CommandErr { fd: "stdin" })?
        .read_to_string(&mut s)?;

    let mut creds = (None, None);

    for line in s.split_terminator('\n') {
        let (k, v) = line.split_once('=').context(SplitErr)?;
        if k == "username" {
            creds.0 = Some(v.to_string());
        } else if k == "password" {
            creds.1 = Some(v.to_string());
        }
    }

    match creds {
        (Some(u), Some(p)) => Ok((u, p)),
        (None, Some(_)) => Err(CredsErr { key: "username" }.build()),
        (Some(_), None) => Err(CredsErr { key: "password" }.build()),
        (None, None) => Err(CredsErr {
            key: "username, password",
        }
        .build()),
    }
}

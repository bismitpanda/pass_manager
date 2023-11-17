use std::{
    io::prelude::*,
    path::PathBuf,
    process::{Command, Stdio},
};

use aes_gcm::{aead::Aead, Aes256Gcm};
use hashbrown::HashMap;
use owo_colors::OwoColorize;
use snafu::{OptionExt, ResultExt};
use url::Url;

use crate::{
    error::{CommandErr, CredsErr, FsErr, HostErr, Result, SplitErr},
    manager::{Manager, ORIGIN},
};

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone)]
#[archive(check_bytes)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Clone)]
#[archive(check_bytes)]
pub struct Remote {
    pub host: String,
    pub url: String,
    pub creds: Option<Credentials>,
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

    pub fn set_remote(&mut self, remote: &str, creds_required: Option<bool>) -> Result<()> {
        if remote == "-" {
            self.remote = None;
        } else {
            let url = Url::parse(remote)?;

            let host = url.host().context(HostErr)?.to_string();

            self.remote = Some(Remote {
                host: host.clone(),
                url: remote.to_string(),
                creds: if creds_required.unwrap_or_else(|| {
                    self.remote
                        .as_ref()
                        .is_some_and(|remote| remote.creds.is_some())
                }) {
                    let (username, password) = get_remote_credentials(&host).map_err(|err| {
                        git2::Error::from_str(&format!("Couldn't get credentials: {err}"))
                    })?;
                    Some(Credentials { username, password })
                } else {
                    None
                },
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

    pub fn to_hashmap(&self) -> HashMap<String, String> {
        let mut map = HashMap::from([
            ("name".to_string(), self.name.clone()),
            ("email".to_string(), self.email.clone()),
        ]);

        if let Some(remote) = &self.remote {
            map.insert("email".to_string(), remote.url.clone());
        }

        map
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
        creds_required: Option<bool>,
    ) -> Result<()> {
        if let Some(name) = name {
            self.user.name = name.clone();
        }

        if let Some(email) = email {
            self.user.email = email.clone();
        }

        if let Some(remote) = remote {
            if remote == "-" {
                if self.repo.find_remote(ORIGIN).is_ok() {
                    self.repo.remote_delete(ORIGIN)?;
                }
            } else if self.repo.find_remote(ORIGIN).is_ok() {
                self.repo.remote_set_url(ORIGIN, remote)?;
            } else {
                self.repo.remote(ORIGIN, remote)?;
            }

            self.user.set_remote(remote, creds_required)?;
        }

        let fields = [
            ("name", name),
            ("email", email),
            ("remote", remote),
            (
                "creds_required",
                &creds_required.map(|value| value.to_string()),
            ),
        ]
        .iter()
        .filter_map(|(name, el)| el.is_some().then_some(*name))
        .collect::<Vec<_>>()
        .join(", ");

        self.fs_dirty = true;
        self.success_message = Some(format!("Successfully set user {fields}"));

        Ok(())
    }
}

pub fn get_remote_credentials(host: &str) -> Result<(String, String)> {
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

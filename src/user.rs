use std::path::PathBuf;

use owo_colors::OwoColorize;
use regex::Regex;
use url::Url;

use crate::manager::Manager;

const EMAIL_RE: &str = r"^[a-zA-Z0-9.!#$%&'*+\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$";

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[archive(check_bytes)]
pub struct User {
    pub name: String,
    pub email: String,
    pub remote: Option<String>,
}

impl User {
    pub fn open(path: &PathBuf) -> Self {
        let buf = std::fs::read(path).unwrap();
        rkyv::from_bytes::<Self>(&buf).unwrap()
    }

    pub fn save(&self, path: &PathBuf) {
        let data = rkyv::to_bytes::<_, 1024>(self).unwrap();
        std::fs::write(path, &data).unwrap();
    }
}

#[allow(clippy::ptr_arg)]
pub fn validate_email(inp: &String) -> Result<(), String> {
    let re = Regex::new(EMAIL_RE).map_err(|err| err.to_string())?;
    re.is_match(inp)
        .then_some(())
        .ok_or_else(|| "invalid email address".to_string())
}

#[allow(clippy::ptr_arg)]
pub fn validate_url(inp: &String) -> Result<(), String> {
    Url::parse(inp).map(|_| ()).map_err(|err| err.to_string())
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
                .unwrap_or_else(|| "Not set".to_string())
                .bright_cyan()
        );
    }

    pub fn set_user(
        &mut self,
        name: &Option<String>,
        email: &Option<String>,
        remote: &Option<String>,
    ) {
        if let Some(name) = name {
            self.user.name = name.clone();
        }

        if let Some(email) = email {
            self.user.email = email.clone();
        }

        if let Some(remote) = remote {
            if self.repo.find_remote("origin").is_ok() {
                self.repo.remote_set_url("origin", remote).unwrap();
            } else {
                self.repo.remote("origin", remote).unwrap();
            }

            self.repo.remote_set_url("origin", remote).unwrap();
            self.user.remote = Some(remote.clone());
        }

        self.user_dirty = true;
    }
}

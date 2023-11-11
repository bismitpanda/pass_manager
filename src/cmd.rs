use std::str::FromStr;

use clap::{Parser, Subcommand, ValueEnum};
use email_address::EmailAddress;
use url::Url;

use crate::styles::STYLES;

/// A Cli based Password Manager with remote sync support
#[derive(Parser)]
#[command(styles = STYLES, author, about, version, long_about = None, propagate_version = true, infer_subcommands = true)]
pub struct Cli {
    #[command(subcommand)]
    pub subcommand: CliSubcommand,
}

impl Cli {
    pub fn to_commit_message(&self) -> String {
        match &self.subcommand {
            CliSubcommand::List
            | CliSubcommand::Initialize
            | CliSubcommand::History
            | CliSubcommand::Copy { .. }
            | CliSubcommand::User(User {
                subcommand: UserSubcommand::Get,
            })
            | CliSubcommand::Store(Store {
                subcommand: StoreSubcommand::Sync { .. } | StoreSubcommand::Nuke { .. },
            }) => String::new(),

            CliSubcommand::Add { ref label, .. } => format!("store add {label}"),
            CliSubcommand::Delete { ref label } => {
                format!("store delete {label}")
            }

            CliSubcommand::Store(Store {
                subcommand: StoreSubcommand::Reset,
            }) => "store reset".to_string(),

            CliSubcommand::Store(Store {
                subcommand: StoreSubcommand::Modify,
            }) => "store modify".to_string(),

            CliSubcommand::User(User {
                subcommand:
                    UserSubcommand::Set {
                        name,
                        email,
                        remote,
                    },
            }) => {
                let fields = [("name", name), ("email", email), ("remote", remote)]
                    .iter()
                    .filter_map(|(name, el)| el.is_some().then_some(*name))
                    .collect::<Vec<_>>()
                    .join(", ");

                format!("user set {fields}")
            }
        }
    }
}

#[derive(Subcommand)]
pub enum CliSubcommand {
    /// Add a new item to the store
    #[command(visible_aliases = ["new", "n"])]
    Add {
        /// take input from user
        #[arg(long, short)]
        input: bool,

        /// length of generated password
        #[arg(long, short = 'n', default_value_t = 12)]
        len: usize,

        /// use special chars in generated password
        #[arg(long, short)]
        special_chars: bool,

        /// overwrite if item already exists
        #[arg(long, short)]
        overwrite: bool,

        /// label of the item
        label: String,
    },

    /// Delete an item from the store
    #[command(visible_aliases = ["dlt", "rm"])]
    Delete {
        /// label of the item
        label: String,
    },

    /// Copy the current password of an item to the clipboard
    #[command(visible_alias = "cp")]
    Copy {
        /// label of the item
        label: String,
    },

    /// List all available items in the store
    #[command(visible_alias = "ls")]
    List,

    /// Initialize the store
    Initialize,

    /// Check history
    #[command(visible_alias = "log")]
    History,

    /// Subcommands concerning the store
    Store(Store),

    /// Subcommands concerning user
    User(User),
}

#[derive(Parser)]
pub struct Store {
    #[command(subcommand)]
    pub subcommand: StoreSubcommand,
}

#[derive(Subcommand)]
pub enum StoreSubcommand {
    /// Reset the store and remove all items
    #[command(visible_alias = "rst")]
    Reset,

    /// Modify the user key used
    #[command(visible_aliases = ["md", "mv"])]
    Modify,

    /// Sync to remote repository
    Sync {
        /// sync store in direction
        #[arg(long, short, value_enum, default_value_t = SyncDirection::Push)]
        dir: SyncDirection,
    },

    /// Remove the store, user data and all git history
    #[group(multiple = false)]
    Nuke {
        /// sync to upstream before nuking
        #[arg(long, short)]
        sync: bool,

        /// archive the directory and save it to pm.tar in the current working directory
        #[arg(long, short)]
        archive: bool,
    },
}

#[derive(ValueEnum, Clone, Copy)]
pub enum SyncDirection {
    Push,
    Pull,
}

#[derive(Parser)]
pub struct User {
    #[command(subcommand)]
    pub subcommand: UserSubcommand,
}

#[derive(Subcommand)]
pub enum UserSubcommand {
    /// Get user details
    Get,

    /// Set/modify user values
    #[group(multiple = true, required = true)]
    Set {
        /// set the name of user
        #[arg(long, short)]
        name: Option<String>,

        /// set the email of user
        #[arg(long, short, value_parser = parse_email)]
        email: Option<String>,

        /// set the remote endpoint of user. (pass "-" to remove any added remote)
        #[arg(long, short, value_parser = parse_remote, allow_hyphen_values = true)]
        remote: Option<String>,
    },
}

fn parse_email(arg: &str) -> Result<String, String> {
    EmailAddress::from_str(arg)
        .map(|_| arg.to_string())
        .map_err(|err| err.to_string())
}

fn parse_remote(arg: &str) -> Result<String, String> {
    if arg != "-" {
        return Url::parse(arg)
            .map(|_| arg.to_string())
            .map_err(|err| err.to_string());
    }

    Ok(arg.to_string())
}

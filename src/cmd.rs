use clap::{Parser, Subcommand};

use crate::styles::STYLES;

#[derive(Parser)]
#[command(styles=STYLES)]
#[command(author, about, version, long_about = None)]
#[command(propagate_version = true, infer_subcommands = true)]
pub struct Cli {
    #[command(subcommand)]
    pub subcommand: CliSubcommand,
}

impl Cli {
    pub fn to_message(&self) -> String {
        match &self.subcommand {
            CliSubcommand::List
            | CliSubcommand::Initialize
            | CliSubcommand::Copy { .. }
            | CliSubcommand::User(User {
                subcommand: UserSubcommand::Get,
            })
            | CliSubcommand::Store(Store {
                subcommand: StoreSubcommand::Sync,
            }) => String::new(),

            CliSubcommand::Add { ref label, .. } => format!("add {label}"),
            CliSubcommand::Delete { ref label } => {
                format!("add {label}")
            }

            CliSubcommand::Store(ref store) => format!(
                "store {}",
                match store.subcommand {
                    StoreSubcommand::Modify => "modify",
                    StoreSubcommand::Reset => "reset",
                    StoreSubcommand::Sync => unreachable!(),
                }
            ),

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
    Sync,
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
        #[arg(long, short)]
        email: Option<String>,

        /// set the remote endpoint of user
        #[arg(long, short)]
        remote: Option<String>,
    },
}

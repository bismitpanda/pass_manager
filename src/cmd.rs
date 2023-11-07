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
        match self.subcommand {
            CliSubcommand::Add { ref label, .. } => format!("add {label}"),
            CliSubcommand::Delete { ref label } => {
                format!("add {label}")
            }

            CliSubcommand::Store(ref store) => format!(
                "store {}",
                match store.subcommand {
                    StoreSubcommand::Modify => "modify",
                    StoreSubcommand::Reset => "reset",
                }
            ),

            _ => String::new(),
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

    /// Subcommands concerning the store
    #[command(visible_alias = "str")]
    Store(Store),
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
}

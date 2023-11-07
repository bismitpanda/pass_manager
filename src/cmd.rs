use std::{fmt::Display, path::PathBuf};

use clap::{Parser, Subcommand, ValueEnum};

use crate::styles::STYLES;

#[derive(Parser)]
#[command(styles=STYLES)]
#[command(author, about, version, long_about = None)]
#[command(propagate_version = true, infer_subcommands = true)]
pub struct Cli {
    #[command(subcommand)]
    pub subcommand: CliSubcommand,
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

    /// Soft delete an item from the store
    #[command(visible_aliases = ["dlt", "rm"])]
    Delete {
        /// label of the item
        label: String,
    },

    /// Hard delete an item from the store
    #[command(visible_alias = "prg")]
    Purge {
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

    /// Restore a deleted item
    Restore {
        /// label of the item to restore
        label: String,
    },

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

    /// Clean up the soft deleted items of the store
    Clean,

    /// Export the store for storage across multiple devices
    Export {
        /// format to export
        #[arg(long, short, value_enum)]
        format: SupportedFormat,

        /// file path to write output
        ///
        /// writes to stdout by default
        #[arg(long, short, value_name = "FILE")]
        out_file: Option<PathBuf>,

        /// use prettified output
        #[arg(long, short)]
        pretty: bool,
    },

    /// Import the store from an exported store file
    Import {
        /// format to import
        #[arg(long, short, value_enum)]
        format: SupportedFormat,

        /// file path to read input
        ///
        /// reads from stdin by default
        #[arg(long, short, value_name = "FILE")]
        in_file: Option<PathBuf>,
    },
}

#[derive(Default, Clone, Copy, ValueEnum)]
pub enum SupportedFormat {
    #[default]
    Json,
    Toml,
    Yaml,
    Ron,
}

impl Display for SupportedFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.to_possible_value()
            .expect("no values are skipped")
            .get_name()
            .fmt(f)
    }
}

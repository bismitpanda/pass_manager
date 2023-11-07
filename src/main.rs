#![warn(clippy::pedantic, clippy::nursery, clippy::all)]
#![allow(clippy::unsafe_derive_deserialize)] // To handle unsafe usage in rkyv `from_bytes_unchecked`

mod cmd;
mod manager;
mod store;
mod styles;
mod table;

use clap::Parser;
use manager::Manager;

use crate::cmd::{Cli, CliSubcommand, Store, StoreSubcommand};

fn main() {
    let command = Cli::parse();
    let mut manager = Manager::new(dirs::data_local_dir().unwrap().join("PassManager"));

    let mut files_dirty = false;

    match &command.subcommand {
        CliSubcommand::Copy { label } => manager.copy(label),

        CliSubcommand::Delete { label } => {
            manager.delete(label);
            files_dirty = true;
        }

        CliSubcommand::List => manager.list(),

        CliSubcommand::Add {
            label,
            input,
            len,
            special_chars,
            overwrite,
        } => {
            manager.add(label, *input, *len, *special_chars, *overwrite);
            files_dirty = true;
        }

        CliSubcommand::Store(Store { subcommand }) => {
            match subcommand {
                StoreSubcommand::Reset => manager.reset(),

                StoreSubcommand::Modify => manager.modify(),
            };
            files_dirty = true;
        }
    }

    if files_dirty {
        manager.cleanup(&command.to_message());
    }
}

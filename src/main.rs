#![warn(clippy::pedantic, clippy::nursery, clippy::all)]

mod cmd;
mod manager;
mod store;
mod styles;
mod table;

use clap::Parser;

use cmd::{Cli, CliSubcommand, Store, StoreSubcommand};
use manager::Manager;

fn main() {
    let command = Cli::parse();
    let mut manager = Manager::new(dirs::data_local_dir().unwrap().join("pm.store"));

    match command.subcommand {
        CliSubcommand::Copy { label } => manager.copy(&label),

        CliSubcommand::Delete { label } => manager.delete(label),

        CliSubcommand::Purge { label } => manager.purge(&label),

        CliSubcommand::List { label } => manager.list(label),

        CliSubcommand::Add {
            label,
            input,
            len,
            special_chars,
            overwrite,
        } => manager.add(&label, input, len, special_chars, overwrite),

        CliSubcommand::Store(Store { subcommand }) => match subcommand {
            StoreSubcommand::Reset => manager.reset(),

            StoreSubcommand::Modify => manager.modify(),

            StoreSubcommand::Clean => manager.clean(),

            StoreSubcommand::Export {
                format,
                out_file,
                pretty,
            } => manager.export(format, out_file, pretty),

            StoreSubcommand::Import { format, in_file } => manager.import(format, in_file),
        },
    }
}

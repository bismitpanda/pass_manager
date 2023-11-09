#![warn(clippy::pedantic, clippy::nursery, clippy::all)]

mod cmd;
mod manager;
mod store;
mod styles;
mod table;
mod user;

use clap::Parser;
use cmd::{User, UserSubcommand};
use manager::Manager;

use crate::cmd::{Cli, CliSubcommand, Store, StoreSubcommand};

fn main() {
    let command = Cli::parse();
    let mut manager = Manager::new(dirs::data_local_dir().unwrap().join("PassManager"));

    match &command.subcommand {
        CliSubcommand::Copy { label } => manager.copy(label),

        CliSubcommand::Delete { label } => {
            manager.delete(label);
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
        }

        CliSubcommand::Store(Store { subcommand }) => {
            match subcommand {
                StoreSubcommand::Reset => manager.reset(),

                StoreSubcommand::Modify => manager.modify(),

                StoreSubcommand::Sync => manager.sync(),
            };
        }

        CliSubcommand::User(User { subcommand }) => match subcommand {
            UserSubcommand::Get => manager.get_user(),

            UserSubcommand::Set {
                name,
                email,
                remote,
            } => manager.set_user(name, email, remote),
        },
    }

    manager.save(&command.to_message());
}

#![warn(clippy::pedantic, clippy::nursery, clippy::all)]

mod cmd;
mod error;
mod manager;
mod store;
mod styles;
mod table;
mod user;

use clap::Parser;
use cmd::{Cli, CliSubcommand, Store, StoreSubcommand, User, UserSubcommand};
use error::{DataDirErr, Result};
use manager::Manager;
use snafu::OptionExt;

fn main() -> Result<()> {
    let command = Cli::parse();
    let mut manager = Manager::new(
        dirs::data_local_dir()
            .context(DataDirErr {})?
            .join("PassManager"),
    )?;

    match &command.subcommand {
        CliSubcommand::Copy { label } => manager.copy(label)?,

        CliSubcommand::Delete { label } => {
            manager.delete(label);
        }

        CliSubcommand::List => manager.list()?,

        CliSubcommand::Add {
            label,
            input,
            len,
            special_chars,
            overwrite,
        } => {
            manager.add(label, *input, *len, *special_chars, *overwrite)?;
        }

        CliSubcommand::Store(Store { subcommand }) => {
            match subcommand {
                StoreSubcommand::Reset => manager.reset()?,

                StoreSubcommand::Modify => manager.modify()?,

                StoreSubcommand::Sync => manager.sync()?,
            };
        }

        CliSubcommand::User(User { subcommand }) => match subcommand {
            UserSubcommand::Get => manager.get_user(),

            UserSubcommand::Set {
                name,
                email,
                remote,
            } => manager.set_user(name, email, remote)?,
        },

        CliSubcommand::Initialize => {}
    }

    manager.save(&command.to_message())
}

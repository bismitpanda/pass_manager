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
use dialoguer::{theme::ColorfulTheme, Confirm};
use error::{DataDirErr, Result};
use manager::Manager;
use owo_colors::OwoColorize;
use snafu::OptionExt;

fn run() -> Result<Option<String>> {
    let command = Cli::parse();

    let data_dir = dirs::data_local_dir()
        .context(DataDirErr)?
        .join("PassManager");

    let mut manager = if data_dir.exists() {
        if matches!(command.subcommand, CliSubcommand::Initialize) {
            return Ok(Some("Store already initialized".to_string()));
        }

        Manager::new(data_dir)?
    } else {
        if matches!(command.subcommand, CliSubcommand::Initialize) {
            Manager::init(data_dir)?;

            return Ok(Some("Successfully initialized store".to_string()));
        }

        println!("{}", "Store doesn't exist.".bright_red());
        if Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Do you want to initialize store?")
            .interact()?
        {
            Manager::init(data_dir)?
        } else {
            return Ok(None);
        }
    };

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

        CliSubcommand::Initialize => (),

        CliSubcommand::History => manager.history()?,

        CliSubcommand::Undo { id } => manager.undo(id)?,

        CliSubcommand::Store(Store { subcommand }) => {
            match subcommand {
                StoreSubcommand::Reset => manager.reset()?,

                StoreSubcommand::Modify => manager.modify()?,

                StoreSubcommand::Sync { dir, force } => manager.sync(*dir, *force)?,

                StoreSubcommand::Nuke { sync, archive } => manager.nuke(*sync, *archive)?,
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
    }

    manager.save(&command.to_commit_message())
}

fn main() {
    match run() {
        Ok(Some(msg)) => println!("{}", msg.bright_green()),
        Err(err) => println!("{}", err.to_string().bright_red()),
        _ => (),
    }
}

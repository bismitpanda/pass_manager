mod cmd;
mod pass_manager;
mod table;

use clap::Parser;
use cmd::Subcommand;
use pass_manager::PasswordManager;

fn main() {
    let cli = cmd::Command::parse();
    let mut manager = PasswordManager::new("meta.bin");

    match cli.subcommand {
        Subcommand::Copy { label } => {
            manager.copy(&label);
        }

        Subcommand::Remove { label } => {
            manager.remove(&label);
        }

        Subcommand::List => {
            manager.list();
        }

        Subcommand::New { label, input, len } => {
            let password = if input {
                rpassword::prompt_password("Enter your password: ").unwrap()
            } else {
                PasswordManager::gen(len)
            };

            manager.add(&label, &password);
        }
    }
}

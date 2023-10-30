mod cmd;
mod manager;
mod table;

fn main() {
    let cli: cmd::Command = cmd::from_args();
    let mut manager = manager::Manager::new(dirs::data_local_dir().unwrap().join("pm.store"));

    match cli.subcommand {
        cmd::Subcommand::Copy(cmd::Copy { label }) => {
            manager.copy(&label);
        }

        cmd::Subcommand::Remove(cmd::Remove { label }) => {
            manager.remove(&label);
        }

        cmd::Subcommand::List => {
            manager.list();
        }

        cmd::Subcommand::New(cmd::New {
            label,
            input,
            len,
            special_chars,
        }) => {
            let password = if input {
                rpassword::prompt_password("Enter your password: ").unwrap()
            } else {
                manager::gen_password(len, special_chars)
            };

            manager.add(&label, &password);
        }

        cmd::Subcommand::Modify => {
            let new_key = rpassword::prompt_password("Enter new key: ").unwrap();
            let retyped_new_key = rpassword::prompt_password("Retype new key: ").unwrap();

            if new_key != retyped_new_key {
                println!("New key doesn't match retyped key")
            } else {
                manager.modify(&new_key);
            }
        }
    }
}

mod pass_manager;
mod table;

use crate::pass_manager::PassManager;
use colored::*;
use std::error::Error;
use std::io::Write;

fn handle_error(res: Result<(), Box<dyn Error>>) {
    match res {
        Ok(_) => {}
        Err(e) => println!("{}", e.to_string().red()),
    }
}

macro_rules! scan_secure {
    ($prompt:literal) => {
        rpassword::prompt_password(format!("{}: ", $prompt)).unwrap()
    };
}

macro_rules! scan {
    ($var:expr, $ident:tt) => {
        print!("{}", $var);
        handle_error(
            std::io::stdout()
                .flush()
                .map_err(|err| err.to_string().into()),
        );
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).unwrap();
        let $ident = String::from(line.trim_end());
    };
}

fn run() -> Result<bool, Box<dyn Error>> {
    println!("{}\n{}\n{}", r"
     ▄▄▄· ▄▄▄· .▄▄ · .▄▄ · ▄▄▌ ▐ ▄▌      ▄▄▄  ·▄▄▄▄    • ▌ ▄ ·.  ▄▄▄·  ▐ ▄  ▄▄▄·  ▄▄ • ▄▄▄ .▄▄▄
    ▐█ ▄█▐█ ▀█ ▐█ ▀. ▐█ ▀. ██· █▌▐█ ▄█▀▄ ▀▄ █·██· ██   ·██ ▐███▪▐█ ▀█ •█▌▐█▐█ ▀█ ▐█ ▀ ▪▀▄.▀·▀▄ █·
     ██▀·▄█▀▀█ ▄▀▀▀█▄▄▀▀▀█▄██▪▐█▐▐▌▐█▌.▐▌▐▀▀▄ ▐█▪ ▐█▌  ▐█ ▌▐▌▐█·▄█▀▀█ ▐█▐▐▌▄█▀▀█ ▄█ ▀█▄▐▀▀▪▄▐▀▀▄
    ▐█▪·•▐█▪ ▐▌▐█▄▪▐█▐█▄▪▐█▐█▌██▐█▌▐█▌.▐▌▐█•█▌██. ██   ██ ██▌▐█▌▐█▪ ▐▌██▐█▌▐█▪ ▐▌▐█▄▪▐█▐█▄▄▌▐█•█▌
    .▀    ▀  ▀  ▀▀▀▀  ▀▀▀▀  ▀▀▀▀ ▀▪ ▀█▄▀▪.▀  ▀▀▀▀▀▀•   ▀▀  █▪▀▀▀ ▀  ▀ ▀▀ █▪ ▀  ▀ ·▀▀▀▀  ▀▀▀ .▀  ▀".blue(),
format!("                                                                                            v{}", env!("CARGO_PKG_VERSION")).bright_cyan(),
"                                                           By: Blood Rogue (github.com/blood-rogue)".green());

    let path = std::path::Path::new(env!("LOCALAPPDATA"))
        .join("PassManager")
        .join("pass_manager");
    // let path = std::path::PathBuf::from("PassManager").join("pass_manager");

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut db = match PassManager::new(path) {
        Ok(db) => db,
        Err(err) => {
            println!("[ERROR]: {}", err.to_string().red());
            return Ok(false);
        }
    };

    loop {
        scan!(">> ", cmd);
        let res: Result<(), Box<dyn Error>> = match cmd.as_str() {
            "help" => db.help(),
            "add" => {
                scan!("Enter label: ", label);
                let password = scan_secure!("Enter password");
                db.add(label, password)
            }
            "remove" => {
                scan!("Enter label: ", label);
                db.remove(label)
            }
            "modify" => {
                scan!("Enter label: ", label);
                let password = scan_secure!("Enter password");
                db.modify(label, password)
            }
            "copy" => {
                scan!("Enter label: ", label);
                db.copy(label)
            }
            "list" => db.list(),
            "reset" => db.reset(),
            "gen" => {
                scan!("Enter label: ", label);
                scan!("Enter the length of password: ", len);
                match len.parse::<usize>() {
                    Ok(len) => db.gen(label, len),
                    Err(err) => Err(err.into()),
                }
            }

            "change" => {
                let cur_key = scan_secure!("Enter current key");
                let new_key = scan_secure!("Enter new key");
                db.change(cur_key, new_key)
            }

            "create" => {
                scan!("Enter username: ", username);
                let password = scan_secure!("Enter new key");
                db.create(username, password)
            }

            "exit" => break db.exit(),

            "logout" => {
                db.exit();
                return Ok(true);
            }

            _ => Err("Invalid subcommand".into()),
        };

        handle_error(res);
    }

    Ok(false)
}

fn main() {
    loop {
        match run() {
            Ok(false) => break,
            Ok(true) => continue,
            Err(err) => handle_error(Err(err)),
        }
    }
}

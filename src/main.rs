mod table;
mod pass_manager;

use crate::pass_manager::PassManager;
use colored::*;
use std::{
    io::Write,
    error::Error
};

fn handle_error(res: Result<(), Box<dyn Error>>) {
    match res {
        Ok(_) => {},
        Err(e) => println!("{}", e.to_string().red())
    }
}

macro_rules! scan_secure {
    ($prompt:literal) => {
        rpassword::prompt_password($prompt).unwrap()
    };
}

fn main() {
    println!("{}\n\n{}v{}\n{}", r"
    ______                                              _     ___  ___
    | ___ \                                            | |    |  \/  |
    | |_/ /  __ _  ___  ___ __      __  ___   _ __   __| |    | .  . |  __ _  _ __    __ _   __ _   ___  _ __
    |  __/  / _` |/ __|/ __|\ \ /\ / / / _ \ | '__| / _` |    | |\/| | / _` || '_ \  / _` | / _` | / _ \| '__|
    | |    | (_| |\__ \\__ \ \ V  V / | (_) || |   | (_| |    | |  | || (_| || | | || (_| || (_| ||  __/| |
    \_|     \__,_||___/|___/  \_/\_/   \___/ |_|    \__,_|    \_|  |_/ \__,_||_| |_| \__,_| \__, | \___||_|
                                                                                             __/ |
                                                                                            |___/".blue(),
"                                                                                                ",
env!("CARGO_PKG_VERSION").bright_cyan(),
"                                                   By: Blood Rogue (github.com/blood-rogue)".green());

    let path = std::path::Path::new(env!("LOCALAPPDATA")).join("pass_manager");
    // let path = std::path::PathBuf::from("pass_manager");

    let mut db = match PassManager::new(path) {
        Ok(db) => db,
        Err(err) => return println!("[ERROR]: {}", err.to_string().red())
    };

    loop {
        let cmd = scan!(>>);
        let res: Result<(), Box<dyn Error>> = match cmd.as_str() {
            "help" => db.help(),
            "add" => {
                let label = scan!("Enter label");
                let password = scan_secure!("Enter password: ");
                db.add(label, password)
            },
            "remove" => {
                let label = scan!("Enter label");
                db.remove(label)
            },
            "modify" => {
                let label = scan!("Enter label");
                let password = scan_secure!("Enter password: ");
                db.modify(label, password)
            },
            "view" => {
                let label = scan!("Enter label");
                db.view(label)
            },
            "list" => db.list(),
            "reset" => db.reset(),
            "gen" => {
                let label = scan!("Enter label");
                match scan!("Enter the length of password").parse::<usize>() {
                    Ok(len) => db.gen(label, len),
                    Err(err) => Err(err.into())
                }
            },
            "exit" => {
                break db.exit();
            },
            _ => Err("Invalid subcommand".into())
        };

        handle_error(res);
    }
}

use colored::*;
use std::{env, error::Error};

mod db;

use crate::db::Database;

fn print_usage() {
    println!("\n{}\n\n{}",
    "Usage: pass [command]".yellow(),
    "Commands:
        help:   Print the help message
        init:   Initialize the password manager
        add:    Add a new password
        remove: Remove a password
        modify: Modify an existing password
        view:   View a password
        list:   List all passwords
        reset:  Reset all passwords".bright_red());
}

fn handle_error(res: Result<(), Box<dyn Error>>) {
    match res {
        Ok(_) => {},
        Err(e) => println!("The following error occured:\n\t{}", e)
    }
}

fn main() {
    println!("{}\n\n{}v{}\n{}", "    ______                                              _     ___  ___                                        
    | ___ \\                                            | |    |  \\/  |                                        
    | |_/ /  __ _  ___  ___ __      __  ___   _ __   __| |    | .  . |  __ _  _ __    __ _   __ _   ___  _ __ 
    |  __/  / _` |/ __|/ __|\\ \\ /\\ / / / _ \\ | '__| / _` |    | |\\/| | / _` || '_ \\  / _` | / _` | / _ \\| '__|
    | |    | (_| |\\__ \\\\__ \\ \\ V  V / | (_) || |   | (_| |    | |  | || (_| || | | || (_| || (_| ||  __/| |   
    \\_|     \\__,_||___/|___/  \\_/\\_/   \\___/ |_|    \\__,_|    \\_|  |_/ \\__,_||_| |_| \\__,_| \\__, | \\___||_|   
                                                                                             __/ |            
                                                                                            |___/             ".blue(),
"                                                                                              ",
env!("CARGO_PKG_VERSION").bright_cyan(),
"                                                   By: Blood Rogue (github.com/blood-rogue)".green());

    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        print_usage();
        return;
    }

    let res: Result<(), Box<dyn Error>> = match args[1].as_str() {
        "help" => {
            print_usage();
            Ok(())
        },
        "init" => Database::init(),
        "add" => Database::add(),
        "remove" => Database::remove(),
        "modify" => Database::modify(),
        "view" => Database::view(),
        "list" => Database::list(),
        "reset" => Database::reset(),
        _ => Result::Err("Invalid subcommand".into())
    };

    handle_error(res);
}

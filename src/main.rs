mod cmd;
mod manager;
mod table;

use clap::Parser;

use cmd::SubCommand;
use manager::Manager;

fn main() {
    let command = cmd::Command::parse();
    let mut manager = Manager::new(dirs::data_local_dir().unwrap().join("pm.store"));

    match command.subcommand {
        SubCommand::Copy { label } => manager.copy(&label),

        SubCommand::Delete { label } => manager.delete(&label),

        SubCommand::List => manager.list(),

        SubCommand::Add {
            label,
            input,
            len,
            special_chars,
        } => manager.add(&label, input, len, special_chars),

        SubCommand::Reset => manager.reset(),

        SubCommand::Modify => manager.modify(),

        SubCommand::Export { format, out_file } => manager.export(format, out_file),

        SubCommand::Import { format, in_file } => manager.import(format, in_file),
    }
}

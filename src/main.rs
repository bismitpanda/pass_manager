mod cmd;
mod manager;
mod table;

use cmd::Subcommand;
use manager::Manager;

fn main() {
    let command = cmd::from_args();
    let mut manager = Manager::new(dirs::data_local_dir().unwrap().join("pm.store"));

    match command.subcommand {
        Subcommand::Copy(cmd::Copy { label }) => manager.copy(&label),

        Subcommand::Delete(cmd::Delete { label }) => manager.delete(&label),

        Subcommand::List => manager.list(),

        Subcommand::Add(cmd::Add {
            label,
            input,
            len,
            special_chars,
        }) => manager.add(&label, input, len, special_chars),

        Subcommand::Reset => manager.reset(),

        Subcommand::Modify => manager.modify(),

        Subcommand::Export(cmd::Export { format, out_file }) => manager.export(format, out_file),

        Subcommand::Import(cmd::Import { format, in_file }) => manager.import(format, in_file),
    }
}

use std::process::exit;

use lexopt::prelude::*;

pub struct Command {
    pub subcommand: Subcommand,
}

pub enum Subcommand {
    New(New),
    Remove(Remove),
    Copy(Copy),
    List,
    Modify,
}

pub struct New {
    pub input: bool,
    pub len: usize,
    pub special_chars: bool,
    pub label: String,
}

pub struct Remove {
    pub label: String,
}

pub struct Copy {
    pub label: String,
}

macro_rules! print_exit {
    ($s:literal, $t:expr) => {{
        println!($s, $t);
        exit(0);
    }};

    ($s:literal) => {{
        println!($s);
        exit(0);
    }};
}

pub fn from_args() -> Command {
    let mut parser = lexopt::Parser::from_env();

    if let Some(Value(val)) = parser.next().unwrap() {
        let subcommand = match val.string().unwrap().as_str() {
            "new" | "n" => {
                let mut new_subcmd = New {
                    input: false,
                    label: String::new(),
                    len: 12,
                    special_chars: false,
                };
                let mut label = None;
                while let Some(arg) = parser.next().unwrap() {
                    match arg {
                        Short('h') | Long("help") => print_exit!("{NEW_HELP}"),
                        Short('i') | Long("input") => new_subcmd.input = true,
                        Short('s') | Long("special-chars") => new_subcmd.special_chars = true,
                        Short('n') | Long("len") => {
                            new_subcmd.len = parser.value().unwrap().parse().unwrap();
                        }
                        Value(val) if label.is_none() => label = Some(val.string().unwrap()),
                        _ => print_exit!("{}", arg.unexpected()),
                    }
                }

                if let Some(label) = label {
                    new_subcmd.label = label;
                } else {
                    print_exit!("No label found\n{NEW_HELP}");
                }

                Subcommand::New(new_subcmd)
            }
            "remove" | "rm" | "r" => {
                let mut label = None;
                while let Some(arg) = parser.next().unwrap() {
                    match arg {
                        Short('h') | Long("help") => print_exit!("{REMOVE_HELP}"),
                        Value(val) if label.is_none() => label = Some(val.string().unwrap()),
                        _ => print_exit!("{}", arg.unexpected()),
                    }
                }

                Subcommand::Remove(Remove {
                    label: label.expect(REMOVE_HELP),
                })
            }
            "copy" | "cp" | "c" => {
                let mut label = None;
                while let Some(arg) = parser.next().unwrap() {
                    match arg {
                        Short('h') | Long("help") => print_exit!("{COPY_HELP}"),
                        Value(val) if label.is_none() => label = Some(val.string().unwrap()),
                        _ => print_exit!("{}", arg.unexpected()),
                    }
                }

                Subcommand::Copy(Copy {
                    label: label.expect(COPY_HELP),
                })
            }
            "list" | "ls" | "l" => {
                let next = parser.next().unwrap();
                if let Some(Short('h') | Long("help")) = next {
                    print_exit!("{LIST_HELP}");
                } else if let Some(arg) = next {
                    print_exit!("{}", arg.unexpected())
                }

                Subcommand::List
            }
            "modify" | "md" | "m" => {
                let next = parser.next().unwrap();
                if let Some(Short('h') | Long("help")) = next {
                    print_exit!("{MODIFY_HELP}");
                } else if let Some(arg) = next {
                    print_exit!("{}", arg.unexpected())
                }

                Subcommand::Modify
            }
            "help" | "h" => {
                if let Some(arg) = parser.next().unwrap() {
                    print_exit!("{}", arg.unexpected())
                }
                print_exit!("{HELP}");
            }

            _ => print_exit!("Unidentified subcommand\n{HELP}"),
        };

        return Command { subcommand };
    } else {
        print_exit!("{HELP}");
    };
}

pub const HELP: &str = "Usage: pm.exe <command> [<args>]

A password manager

Commands:
  help, h               display usage information
  new, n                Add a new entry
  remove, rm, r         Remove an entry
  copy, cp, c           Copy an entry to clipboard
  list, ls, l           List entries
  modify, md, m         Modify current password";

pub const NEW_HELP: &str = "Usage: pm.exe (new/n) <label> [-i] [-n <len>] [-s]

Add a new entry

Positional Arguments:
  label                 label of the entry

Options:
  -i, --input           input from user
  -n, --len             length of generated password
  -s, --special-chars   include special chars
  -h, --help            display usage information";

pub const REMOVE_HELP: &str = "Usage: pm.exe (remove/rm/r) <label>

Remove an entry

Positional Arguments:
  label                 label of the entry

Options:
  -h, --help            display usage information";

pub const COPY_HELP: &str = "Usage: pm.exe (copy/cp/c) <label>

Copy an entry to clipboard

Positional Arguments:
  label                 label of the entry

Options:
  -h, --help            display usage information";

pub const LIST_HELP: &str = "Usage: pm.exe (list/ls/l)

List entries

Options:
  -h, --help            display usage information";

pub const MODIFY_HELP: &str = "Usage: pm.exe (modify/md/m)

Modify Password

Options:
  -h, --help            display usage information";

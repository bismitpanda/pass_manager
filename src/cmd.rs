use std::{path::PathBuf, process::exit, str::FromStr};

use lexopt::prelude::*;
use owo_colors::OwoColorize;

pub struct Command {
    pub subcommand: Subcommand,
}

pub enum Subcommand {
    Add(Add),
    Delete(Delete),
    Copy(Copy),
    List,
    Reset,
    Modify,
    Export(Export),
    Import(Import),
}

#[derive(Default)]
pub struct Add {
    pub input: bool,
    pub len: usize,
    pub special_chars: bool,
    pub label: String,
}

pub struct Delete {
    pub label: String,
}

pub struct Copy {
    pub label: String,
}

macro_rules! print_exit {
    ($($arg:tt)*) => {{
        println!($($arg)*);
        exit(0);
    }};
}

#[derive(Default, Clone, Copy)]
pub enum SupportedFormat {
    #[default]
    Json,
    Toml,
    Yaml,
}

impl FromStr for SupportedFormat {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "json" => Ok(Self::Json),
            "toml" => Ok(Self::Toml),
            "yml" | "yaml" => Ok(Self::Yaml),
            _ => Err(format!("'{s}' is not supported")),
        }
    }
}

#[derive(Default)]
pub struct Export {
    pub format: SupportedFormat,
    pub out_file: PathBuf,
}

#[derive(Default)]
pub struct Import {
    pub format: SupportedFormat,
    pub in_file: PathBuf,
}

pub fn from_args() -> Command {
    let mut parser = lexopt::Parser::from_env();

    if let Some(arg) = parser.next().unwrap() {
        match arg {
            Value(val) => {
                let val_str = val.string().unwrap();
                let subcommand = match val_str.as_str() {
                    "add" | "a" => {
                        let mut add_subcmd = Add {
                            len: 12,
                            ..Add::default()
                        };

                        let mut label = None;
                        while let Some(arg) = parser.next().unwrap() {
                            match arg {
                                Short('h') | Long("help") => {
                                    print_exit!("{}", ADD_HELP.bright_green())
                                }
                                Short('i') | Long("input") => add_subcmd.input = true,
                                Short('s') | Long("special-chars") => {
                                    add_subcmd.special_chars = true;
                                }
                                Short('n') | Long("len") => {
                                    add_subcmd.len = parser.value().unwrap().parse().unwrap();
                                }
                                Value(val) if label.is_none() => {
                                    label = Some(val.string().unwrap());
                                }
                                _ => print_exit!(
                                    "{}\n{}",
                                    arg.unexpected().bright_red(),
                                    ADD_HELP.bright_green()
                                ),
                            }
                        }

                        if let Some(label) = label {
                            add_subcmd.label = label;
                        } else {
                            print_exit!(
                                "{}\n{}",
                                "No label found".bright_red(),
                                ADD_HELP.bright_green()
                            );
                        }

                        Subcommand::Add(add_subcmd)
                    }

                    "delete" | "dl" | "d" => {
                        let mut label = None;
                        while let Some(arg) = parser.next().unwrap() {
                            match arg {
                                Short('h') | Long("help") => {
                                    print_exit!("{}", DELETE_HELP.bright_green())
                                }
                                Value(val) if label.is_none() => {
                                    label = Some(val.string().unwrap());
                                }
                                _ => print_exit!(
                                    "{}\n{}",
                                    arg.unexpected().bright_red(),
                                    DELETE_HELP.bright_green()
                                ),
                            }
                        }

                        Subcommand::Delete(Delete {
                            label: label.map_or_else(
                                || {
                                    print_exit!(
                                        "{}\n{}",
                                        "No label found".bright_red(),
                                        DELETE_HELP.bright_green()
                                    )
                                },
                                |label| label,
                            ),
                        })
                    }

                    "copy" | "cp" | "c" => {
                        let mut label = None;
                        while let Some(arg) = parser.next().unwrap() {
                            match arg {
                                Short('h') | Long("help") => {
                                    print_exit!("{}", COPY_HELP.bright_green())
                                }
                                Value(val) if label.is_none() => {
                                    label = Some(val.string().unwrap());
                                }
                                _ => print_exit!(
                                    "{}\n{}",
                                    arg.unexpected().bright_red(),
                                    COPY_HELP.bright_green()
                                ),
                            }
                        }

                        Subcommand::Copy(Copy {
                            label: label.map_or_else(
                                || {
                                    print_exit!(
                                        "{}\n{}",
                                        "No label found".bright_red(),
                                        COPY_HELP.bright_green()
                                    )
                                },
                                |label| label,
                            ),
                        })
                    }

                    "list" | "ls" | "l" => {
                        let next = parser.next().unwrap();
                        if let Some(Short('h') | Long("help")) = next {
                            print_exit!("{}", LIST_HELP.bright_green());
                        } else if let Some(arg) = next {
                            print_exit!(
                                "{}\n{}",
                                arg.unexpected().bright_red(),
                                LIST_HELP.bright_green()
                            )
                        }

                        Subcommand::List
                    }

                    "reset" | "rst" | "r" => {
                        let next = parser.next().unwrap();
                        if let Some(Short('h') | Long("help")) = next {
                            print_exit!("{}", RESET_HELP.bright_green());
                        } else if let Some(arg) = next {
                            print_exit!(
                                "{}\n{}",
                                arg.unexpected().bright_red(),
                                RESET_HELP.bright_green()
                            )
                        }

                        Subcommand::Reset
                    }

                    "modify" | "md" | "m" => {
                        let next = parser.next().unwrap();
                        if let Some(Short('h') | Long("help")) = next {
                            print_exit!("{}", MODIFY_HELP.bright_green());
                        } else if let Some(arg) = next {
                            print_exit!(
                                "{}\n{}",
                                arg.unexpected().bright_red(),
                                MODIFY_HELP.bright_green()
                            )
                        }

                        Subcommand::Modify
                    }

                    "help" | "h" => parser.next().unwrap().map_or_else(
                        || print_exit!("{}", HELP.bright_green()),
                        |arg| {
                            print_exit!(
                                "{}\n{}",
                                arg.unexpected().bright_red(),
                                HELP.bright_green()
                            )
                        },
                    ),

                    "export" | "exp" | "e" => {
                        let mut export_subcmd = Export::default();

                        while let Some(arg) = parser.next().unwrap() {
                            match arg {
                                Short('h') | Long("help") => {
                                    print_exit!("{}", EXPORT_HELP.bright_green())
                                }
                                Short('f') | Long("format") => {
                                    export_subcmd.format = parser.value().unwrap().parse().unwrap();
                                }
                                Short('o') | Long("out-file") => {
                                    export_subcmd.out_file =
                                        parser.value().unwrap().parse().unwrap();
                                }
                                _ => print_exit!(
                                    "{}\n{}",
                                    arg.unexpected().bright_red(),
                                    EXPORT_HELP.bright_green()
                                ),
                            }
                        }

                        Subcommand::Export(export_subcmd)
                    }

                    "import" | "imp" | "i" => {
                        let mut import_subcmd = Import::default();

                        while let Some(arg) = parser.next().unwrap() {
                            match arg {
                                Short('h') | Long("help") => {
                                    print_exit!("{}", IMPORT_HELP.bright_green())
                                }
                                Short('f') | Long("format") => {
                                    import_subcmd.format = parser.value().unwrap().parse().unwrap();
                                }
                                Short('i') | Long("in-file") => {
                                    import_subcmd.in_file =
                                        parser.value().unwrap().parse().unwrap();
                                }
                                _ => print_exit!(
                                    "{}\n{}",
                                    arg.unexpected().bright_red(),
                                    IMPORT_HELP.bright_green()
                                ),
                            }
                        }

                        Subcommand::Import(import_subcmd)
                    }

                    _ => print_exit!(
                        "{} '{}'\n{}",
                        "Unidentified subcommand".bright_red(),
                        val_str.bright_blue(),
                        HELP.bright_green()
                    ),
                };

                Command { subcommand }
            }

            Short('?' | 'h') | Long("help") => {
                print_exit!("{}", HELP.bright_green())
            }

            Short(s) => {
                print_exit!(
                    "{} {}\n{}",
                    "Invalid option".bright_red(),
                    format!("'-{s}'").bright_blue(),
                    HELP.bright_green()
                )
            }

            Long(l) => {
                print_exit!(
                    "{} {}\n{}",
                    "Invalid option".bright_red(),
                    format!("'--{l}'").bright_blue(),
                    HELP.bright_green()
                )
            }
        }
    } else {
        print_exit!("{}", HELP.bright_green());
    }
}

const HELP: &str = "Usage: pm.exe <command> [<args>]

A password manager

Options:
  -?, -h, --help        display usage information

Commands:
  h, help               display usage information
  a, add                Add a new record
  c, cp, copy           Copy a record to clipboard
  l, ls, list           List records
  m, md, modify         Modify current password
  d, dl, delete         Delete a record
  r, rst, reset         Reset password store
  e, exp, export        Export the password store
  i, imp, import        Import the password store";

const ADD_HELP: &str = "Usage: pm.exe (add/a) <label> [-i] [-n <len>] [-s]

Add a new record

Positional Arguments:
  label                 label of the record

Options:
  -i, --input           input from user
  -n, --len             length of generated password
  -s, --special-chars   include special chars
  -h, --help            display usage information";

const DELETE_HELP: &str = "Usage: pm.exe (delete/dl/d) <label>

Delete a record

Positional Arguments:
  label                 label of the record

Options:
  -h, --help            display usage information";

const COPY_HELP: &str = "Usage: pm.exe (copy/cp/c) <label>

Copy a record to clipboard

Positional Arguments:
  label                 label of the record

Options:
  -h, --help            display usage information";

const LIST_HELP: &str = "Usage: pm.exe (list/ls/l)

List records

Options:
  -h, --help            display usage information";

const RESET_HELP: &str = "Usage: pm.exe (reset/rst/r)

Reset password store

Options:
  -h, --help            display usage information";

const MODIFY_HELP: &str = "Usage: pm.exe (modify/md/m)

Modify current Password

Options:
  -h, --help            display usage information";

const EXPORT_HELP: &str = "Usage: pm.exe (export/exp/e)

Export the password store

Options:
  -f, --format          format to export to [json, toml, yaml, yml]
  -o, --out-file        file path to write output
  -h, --help            display usage information";

const IMPORT_HELP: &str = "Usage: pm.exe (import/imp/i)

Import the password store

Options:
  -f, --format          format to import from [json, toml, yaml, yml]
  -i, --in-file         file path to read input
  -h, --help            display usage information";

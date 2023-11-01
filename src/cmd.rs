use std::{path::PathBuf, str::FromStr};

use clap::{builder::Styles, Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(styles=get_styles())]
pub struct Command {
    #[command(subcommand)]
    pub subcommand: SubCommand,
}

#[derive(Subcommand)]
pub enum SubCommand {
    #[command(visible_aliases = ["new", "n", "a"])]
    Add {
        #[arg(long, short)]
        input: bool,
        #[arg(long, short = 'n', default_value_t = 12)]
        len: usize,
        #[arg(long, short)]
        special_chars: bool,
        label: String,
    },

    #[command(visible_aliases = ["dlt", "d", "rm"])]
    Delete { label: String },

    #[command(visible_aliases = ["cp", "c"])]
    Copy { label: String },

    #[command(visible_aliases = ["ls", "l"])]
    List,

    #[command(visible_aliases = ["rst", "r"])]
    Reset,

    #[command(visible_aliases = ["md", "mv", "m"])]
    Modify,

    #[command(visible_aliases = ["exp", "e"])]
    Export {
        #[arg(long, short)]
        format: SupportedFormat,

        #[arg(long, short, value_name = "FILE")]
        out_file: Option<PathBuf>,
    },

    #[command(visible_aliases = ["imp", "i"])]
    Import {
        #[arg(long, short)]
        format: SupportedFormat,

        #[arg(long, short, value_name = "FILE")]
        in_file: Option<PathBuf>,
    },
}

#[derive(Default, Clone, Copy, ValueEnum)]
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

const fn get_styles() -> Styles {
    Styles::styled()
        .usage(
            anstyle::Style::new()
                .bold()
                .underline()
                .fg_color(Some(anstyle::Color::Ansi(anstyle::AnsiColor::BrightYellow))),
        )
        .header(
            anstyle::Style::new()
                .bold()
                .underline()
                .fg_color(Some(anstyle::Color::Ansi(anstyle::AnsiColor::BrightYellow))),
        )
        .literal(
            anstyle::Style::new()
                .fg_color(Some(anstyle::Color::Ansi(anstyle::AnsiColor::BrightGreen))),
        )
        .invalid(
            anstyle::Style::new()
                .bold()
                .fg_color(Some(anstyle::Color::Ansi(anstyle::AnsiColor::BrightRed))),
        )
        .error(
            anstyle::Style::new()
                .bold()
                .fg_color(Some(anstyle::Color::Ansi(anstyle::AnsiColor::BrightRed))),
        )
        .valid(
            anstyle::Style::new()
                .bold()
                .underline()
                .fg_color(Some(anstyle::Color::Ansi(anstyle::AnsiColor::BrightGreen))),
        )
        .placeholder(
            anstyle::Style::new()
                .fg_color(Some(anstyle::Color::Ansi(anstyle::AnsiColor::BrightWhite))),
        )
}

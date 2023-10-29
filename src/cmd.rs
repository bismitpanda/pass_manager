#[derive(clap::Parser)]
pub struct Command {
    #[command(subcommand)]
    pub subcommand: Subcommand,
}

#[derive(clap::Subcommand)]
pub enum Subcommand {
    #[command(visible_alias = "n")]
    New {
        label: String,

        #[arg(long, short)]
        input: bool,

        #[arg(long, short = 'n', default_value_t = 12)]
        len: usize,
    },

    #[command(visible_aliases = ["r", "rm", "rmv"])]
    Remove { label: String },

    #[command(visible_aliases = ["c", "cp"])]
    Copy { label: String },

    #[command(visible_aliases = ["l", "ls"])]
    List,
}

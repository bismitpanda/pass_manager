use std::io::{BufWriter, Write};

use owo_colors::OwoColorize;
use snafu::OptionExt;

use crate::error::{Result, SplitErr};

const TOP_LEFT_CORNER: &str = "╭";
const TOP_RIGHT_CORNER: &str = "╮";
const BOTTOM_LEFT_CORNER: &str = "╰";
const BOTTOM_RIGHT_CORNER: &str = "╯";

const HORIZONTAL_BAR: &str = "─";
const VERTICAL_BAR: &str = "│";

const VERTICAL_LEFT_JOINT: &str = "├";
const VERTICAL_RIGHT_JOINT: &str = "┤";
const HORIZONTAL_TOP_JOINT: &str = "┬";
const HORIZONTAL_BOTTOM_JOINT: &str = "┴";

const INTERSECTION: &str = "┼";

pub struct Table<const N: usize> {
    headers: [String; N],
    rows: Vec<[String; N]>,
    maxes: [usize; N],
}

impl<const N: usize> Table<N> {
    pub fn new(headers: [String; N]) -> Self {
        let mut maxes = [0; N];
        for (i, header) in headers.iter().enumerate() {
            maxes[i] = header.len();
        }

        Self {
            rows: Vec::new(),
            headers,
            maxes,
        }
    }

    pub fn insert(&mut self, row: [String; N]) {
        for (i, cell) in row.iter().enumerate() {
            let n = cell.len();
            if n > self.maxes[i] {
                self.maxes[i] = n;
            }
        }

        self.rows.push(row);
    }

    pub fn display(self) -> Result<()> {
        let mut buf = BufWriter::new(Vec::new());

        let (&last_max, rest_maxes) = self.maxes.split_last().context(SplitErr {})?;

        write!(buf, "{}", TOP_LEFT_CORNER.bright_yellow())?;
        for &max in rest_maxes {
            write!(
                buf,
                "{}{}",
                HORIZONTAL_BAR.repeat(max + 2).bright_yellow(),
                HORIZONTAL_TOP_JOINT.bright_yellow()
            )?;
        }

        write!(
            buf,
            "{}{}\n{}",
            HORIZONTAL_BAR.repeat(last_max + 2).bright_yellow(),
            TOP_RIGHT_CORNER.bright_yellow(),
            VERTICAL_BAR.bright_yellow()
        )?;

        for (i, data) in self.headers.iter().enumerate() {
            write!(
                buf,
                " {:^max$} {}",
                data.bright_cyan(),
                VERTICAL_BAR.bright_yellow(),
                max = self.maxes[i]
            )?;
        }
        write!(buf, "\n{}", VERTICAL_LEFT_JOINT.bright_yellow())?;
        for (j, _) in self.headers.iter().enumerate() {
            write!(
                buf,
                "{}",
                HORIZONTAL_BAR.repeat(self.maxes[j] + 2).bright_yellow()
            )?;
            if j != self.headers.len() - 1 {
                write!(buf, "{}", INTERSECTION.bright_yellow())?;
            }
        }
        writeln!(buf, "{}", VERTICAL_RIGHT_JOINT.bright_yellow())?;

        let len = self.rows.len();

        for (i, row) in self.rows.iter().enumerate() {
            write!(buf, "{}", VERTICAL_BAR.bright_yellow())?;
            for (i, data) in row.iter().enumerate() {
                write!(
                    buf,
                    " {data:^max$} {}",
                    VERTICAL_BAR.bright_yellow(),
                    max = self.maxes[i]
                )?;
            }
            writeln!(buf)?;
            if i != len - 1 {
                write!(buf, "{}", VERTICAL_LEFT_JOINT.bright_yellow())?;
                let row_len = row.len();
                for (j, _) in row.iter().enumerate() {
                    write!(
                        buf,
                        "{}",
                        HORIZONTAL_BAR.repeat(self.maxes[j] + 2).bright_yellow()
                    )?;
                    if j != row_len - 1 {
                        write!(buf, "{}", INTERSECTION.bright_yellow())?;
                    }
                }
                writeln!(buf, "{}", VERTICAL_RIGHT_JOINT.bright_yellow())?;
            }
        }

        write!(buf, "{}", BOTTOM_LEFT_CORNER.bright_yellow())?;
        for &max in rest_maxes {
            write!(
                buf,
                "{}{}",
                HORIZONTAL_BAR.repeat(max + 2).bright_yellow(),
                HORIZONTAL_BOTTOM_JOINT.bright_yellow()
            )?;
        }

        writeln!(
            buf,
            "{}{}",
            HORIZONTAL_BAR.repeat(last_max + 2).bright_yellow(),
            BOTTOM_RIGHT_CORNER.bright_yellow()
        )?;

        std::io::stdout().write_all(buf.buffer())?;

        Ok(())
    }
}

use std::io::{BufWriter, Write};

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

    pub fn display(self) {
        let mut buf = BufWriter::new(Vec::new());

        let (&last_max, rest_maxes) = self.maxes.split_last().unwrap();

        write!(buf, "{TOP_LEFT_CORNER}").unwrap();
        for &max in rest_maxes {
            write!(
                buf,
                "{}{HORIZONTAL_TOP_JOINT}",
                HORIZONTAL_BAR.repeat(max + 2)
            )
            .unwrap();
        }

        writeln!(
            buf,
            "{:last_max$}{TOP_RIGHT_CORNER}",
            HORIZONTAL_BAR.repeat(last_max + 2)
        )
        .unwrap();

        write!(buf, "{VERTICAL_BAR}").unwrap();
        for (i, data) in self.headers.iter().enumerate() {
            write!(buf, " {data:^max$} {VERTICAL_BAR}", max = self.maxes[i]).unwrap();
        }
        write!(buf, "\n{VERTICAL_LEFT_JOINT}").unwrap();
        for (j, _) in self.headers.iter().enumerate() {
            write!(buf, "{}", HORIZONTAL_BAR.repeat(self.maxes[j] + 2)).unwrap();
            if j != self.headers.len() - 1 {
                write!(buf, "{INTERSECTION}").unwrap();
            }
        }
        writeln!(buf, "{VERTICAL_RIGHT_JOINT}").unwrap();

        let len = self.rows.len();

        for (i, row) in self.rows.iter().enumerate() {
            write!(buf, "{VERTICAL_BAR}").unwrap();
            for (i, data) in row.iter().enumerate() {
                write!(buf, " {data:^max$} {VERTICAL_BAR}", max = self.maxes[i]).unwrap();
            }
            writeln!(buf).unwrap();
            if i != len - 1 {
                write!(buf, "{VERTICAL_LEFT_JOINT}").unwrap();
                let row_len = row.len();
                for (j, _) in row.iter().enumerate() {
                    write!(buf, "{}", HORIZONTAL_BAR.repeat(self.maxes[j] + 2)).unwrap();
                    if j != row_len - 1 {
                        write!(buf, "{INTERSECTION}").unwrap();
                    }
                }
                writeln!(buf, "{VERTICAL_RIGHT_JOINT}").unwrap();
            }
        }

        write!(buf, "{BOTTOM_LEFT_CORNER}").unwrap();
        for &max in rest_maxes {
            write!(
                buf,
                "{}{HORIZONTAL_BOTTOM_JOINT}",
                HORIZONTAL_BAR.repeat(max + 2)
            )
            .unwrap();
        }

        writeln!(
            buf,
            "{:last_max$}{BOTTOM_RIGHT_CORNER}",
            HORIZONTAL_BAR.repeat(last_max + 2)
        )
        .unwrap();

        println!("{}", String::from_utf8(buf.buffer().to_vec()).unwrap());
    }
}

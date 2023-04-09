use std::error::Error;

use colored::Colorize;

const TOP_LEFT_CORNER: &'static str = "╭";
const TOP_RIGHT_CORNER: &'static str = "╮";
const BOTTOM_LEFT_CORNER: &'static str = "╰";
const BOTTOM_RIGHT_CORNER: &'static str = "╯";

const HORIZONTAL_BAR: &'static str = "─";
const VERTICAL_BAR: &'static str = "│";

const VERTICAL_LEFT_JOINT: &'static str = "├";
const VERTICAL_RIGHT_JOINT: &'static str = "┤";
const HORIZONTAL_TOP_JOINT: &'static str = "┬";
const HORIZONTAL_BOTTOM_JOINT: &'static str = "┴";

const INTERSECTION: &'static str = "┼";

pub struct Table {
    headers: Vec<String>,
    rows: Vec<Vec<String>>
}

impl Table {
    pub fn new(headers: Vec<String>) -> Self {
        Self {
            rows: Vec::new(),
            headers
        }
    }

    pub fn insert(&mut self, row: Vec<String>) {
        self.rows.push(row)
    }

    fn check(&self) -> Result<(), Box<dyn Error>> {
        let n = self.headers.len();
        for row in &self.rows {
            if n != row.len() {
                return Err("invalid length of row".into());
            }
        }

        Ok(())
    }

    fn calc_max(&self) -> Result<Vec<usize>, Box<dyn Error>> {
        let mut maxes: Vec<_> = self.headers.iter().map(String::len).collect();

        for row in &self.rows {
            for (i, data) in row.iter().enumerate() {
                if data.len() > maxes[i] {
                    maxes[i] = data.len()
                }
            }
        };

        Ok(maxes.iter().map(|&max| max + 2).collect())
    }

    pub fn display(self) -> Result<(), Box<dyn Error>> {
        self.check()?;

        let maxes = self.calc_max()?;
        let (&last_max, rest_maxes) = maxes.split_last().unwrap();

        print!("{}", TOP_LEFT_CORNER.yellow());
        for &max in rest_maxes {
            print!("{}", HORIZONTAL_BAR.repeat(max).yellow());
            print!("{}", HORIZONTAL_TOP_JOINT.yellow());
        }

        print!("{:last_max$}", HORIZONTAL_BAR.repeat(last_max).yellow());
        println!("{}", TOP_RIGHT_CORNER.yellow());

        print!("{}", VERTICAL_BAR.yellow());
        for (i, data) in self.headers.iter().enumerate() {
            print!("{:^max$}{}", data.bold().blue(), VERTICAL_BAR.yellow(), max = maxes[i]);
        }
        println!();

        print!("{}", VERTICAL_LEFT_JOINT.yellow());
        for (j, _) in self.headers.iter().enumerate() {
            print!("{}", HORIZONTAL_BAR.repeat(maxes[j]).yellow());
            if j != self.headers.len() - 1 {
                print!("{}", INTERSECTION.yellow());
            }
        }
        println!("{}", VERTICAL_RIGHT_JOINT.yellow());

        let len = self.rows.len();

        for (i, row) in self.rows.iter().enumerate() {
            print!("{}", VERTICAL_BAR.yellow());
            for (i, data) in row.iter().enumerate() {
                print!("{data:^max$}{}", VERTICAL_BAR.yellow(), max = maxes[i]);
            }
            println!();
            if i != len - 1 {
                print!("{}", VERTICAL_LEFT_JOINT.yellow());
                let row_len = row.len();
                for (j, _) in row.iter().enumerate() {
                    print!("{}", HORIZONTAL_BAR.repeat(maxes[j]).yellow());
                    if j != row_len - 1 {
                        print!("{}", INTERSECTION.yellow());
                    }
                }
                println!("{}", VERTICAL_RIGHT_JOINT.yellow());
            }
        }

        print!("{}", BOTTOM_LEFT_CORNER.yellow());
        for &max in rest_maxes {
            print!("{}", HORIZONTAL_BAR.repeat(max).yellow());
            print!("{}", HORIZONTAL_BOTTOM_JOINT.yellow());
        }

        print!("{:last_max$}", HORIZONTAL_BAR.repeat(last_max).yellow());
        println!("{}", BOTTOM_RIGHT_CORNER.yellow());

        Ok(())
    }
}
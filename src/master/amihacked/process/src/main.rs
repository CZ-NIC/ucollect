extern crate csv;
extern crate regex;

use std::process::*;
use std::thread;
use std::sync::*;
use regex::Regex;

fn main() {
    let mut running = Vec::new();
    for arg in std::env::args() {
        let a_cp = arg.clone();
        let prefix = Regex::new(r"^(.[^.]?)").unwrap();
        running.push(thread::spawn(move || {
            let mut unzip = Command::new("pbzip2").arg("-dc").arg(a_cp).stdout(Stdio::piped()).spawn().expect("Failed to start unzip");
            {
                let mut output = unzip.stdout.as_mut().unwrap();
                let mut reader = csv::Reader::from_reader(&mut output);

                for row in reader.records() {
                    let row = row.unwrap();
                    let iprefix = prefix.captures(&row[0]).expect("Doesn't match").at(1).unwrap();
                    println!("{} {}", &row[0], iprefix);
                }
            }

            unzip.wait_with_output().expect("Failed to wait for unzip");
        }));
    }
    for t in running {
        t.join().expect("Failure in a thread");
    }
}

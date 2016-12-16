extern crate csv;

use std::process::*;
use std::thread;

fn main() {
    let mut running = Vec::new();
    for arg in std::env::args() {
        let a_cp = arg.clone();
        running.push(thread::spawn(move || {
            let mut unzip = Command::new("pbzip2").arg("-dc").arg(a_cp).stdout(Stdio::piped()).spawn().expect("Failed to start unzip");
            {
                let mut output = unzip.stdout.as_mut().unwrap();
                let mut reader = csv::Reader::from_reader(&mut output);

                for row in reader.records() {
                    println!("{:?}", row);
                }
            }

            unzip.wait_with_output().expect("Failed to wait for unzip");
        }));
    }
    for t in running {
        t.join().expect("Failure in a thread");
    }
}

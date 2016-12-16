/*!
 * This takes several compressed CSV inputs in the form:
 *
 * ```text
 * 1.2.3.4,2016-02-02,3,ssh
 * 192.0.2.1,2016-12-02,1,telnet
 * ...
 * ```
 *
 * It splits these files into same format of CSV files, but
 * by the fist two letters of the IP address (ignoring the dot
 * in case of single-digit octet). The goal is a kind of
 * load-balancing the data into files, but making sure the same
 * IP addresses are together in the same file.
 */

extern crate csv;
extern crate regex;

use std::process::*;
use std::thread;
use std::sync::*;
use std::collections::HashMap;
use std::io::Write;
use regex::Regex;

/**
 * Object representing output writer into a file. It compresses
 * the data as it goes.
 */
struct SplitOutput {
    compressor: Child
}

impl SplitOutput {
    fn new(name: &str) -> SplitOutput {
        SplitOutput { compressor: Command::new("/bin/sh").arg("-c").arg(format!("gzip >{}.csv.gz", name)).stdin(Stdio::piped()).spawn().expect("Failed to start gzip") }
    }
    /// Write some data into the file.
    fn process(&mut self, data: &Vec<String>) {
        write!(self.compressor.stdin.as_mut().unwrap(), "{},{},{},{}\n", data[0], data[1], data[2], data[3]).expect("Write error");
    }
}

impl Drop for SplitOutput {
    /// Make sure we wait for everything before we finish up.
    fn drop(&mut self) {
        self.compressor.wait().expect("Output wait error");
    }
}

fn main() {
    // For threads.
    let mut running = Vec::new();
    // Currently output files.
    /*
     * TODO: Could I get rid of that Arc thing? I know I join the
     * threads before this goes out of scope.
     */
    let outputs: Arc<RwLock<HashMap<String, Mutex<SplitOutput>>>> = Arc::new(RwLock::new(HashMap::new()));
    for arg in std::env::args().skip(1) {
        let a_cp = arg.clone();
        let outputs = outputs.clone();
        // Run the input files in parallel
        running.push(thread::spawn(move || {
            let prefix = Regex::new(r"^(.[^.]?)").unwrap();
            let mut unzip = Command::new("/usr/bin/pbzip2").arg("-dc").arg(a_cp).stdout(Stdio::piped()).spawn().expect("Failed to start unzip");
            {
                let mut output = unzip.stdout.as_mut().unwrap();
                let mut reader = csv::Reader::from_reader(&mut output).has_headers(false);

                for row in reader.records() {
                    let row = row.unwrap();
                    let iprefix = prefix.captures(&row[0]).expect("Doesn't match").at(1).unwrap();
                    /*
                     * First take read lock on the whole map and look up the opened output
                     * file for the IP prefix. On the very rare occasion it is not yet opened,
                     * get rid of the read lock (that's the reason for the block in the if
                     * condition), get a write lock instead. Make sure noone else
                     * created the opened file in the meantime when we didn't have it locked
                     * and if not, create a new one.
                     */
                    if {
                        if let Some(output) = outputs.read().unwrap().get(iprefix) {
                            output.lock().unwrap().process(&row);
                            false
                        } else {
                            true
                        }
                    } {
                        let mut wlock = outputs.write().unwrap();
                        wlock.entry(String::from(iprefix)).or_insert_with(|| Mutex::new(SplitOutput::new(iprefix))).lock().unwrap().process(&row);
                    }
                }
            }

            unzip.wait_with_output().expect("Failed to wait for unzip");
        }));
    }
    // Wait for background threads.
    for t in running {
        t.join().expect("Failure in a thread");
    }
}

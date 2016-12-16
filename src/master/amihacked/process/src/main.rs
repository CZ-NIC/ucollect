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
 *
 * As it is a small utility for rare manual run, most errors
 * simply panic through unwrap() or expect(). We would terminate
 * the program anyway.
 */

extern crate csv;
extern crate regex;
extern crate scoped_pool;

use std::process::*;
use std::sync::*;
use std::collections::{HashMap,HashSet};
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
    /**
     * Create a new SplitOutput. It openes the compressor and stores its output. The name is the
     * prefix of the file.
     */
    fn new(name: &str) -> SplitOutput {
        SplitOutput { compressor: Command::new("/bin/sh").arg("-c").arg(format!("gzip >{}.csv.gz", name)).stdin(Stdio::piped()).spawn().expect("Failed to start gzip") }
    }
    /// Write some data into the file.
    fn process(&mut self, data: &[String]) {
        write!(self.compressor.stdin.as_mut().unwrap(), "{},{},{},{}\n", data[0], data[1], data[2], data[3]).expect("Write error");
    }
}

impl Drop for SplitOutput {
    /// Make sure we wait for everything before we finish up.
    fn drop(&mut self) {
        self.compressor.wait().expect("Output wait error");
    }
}

/// Bunch of outputs to store into.
type Splitter = RwLock<HashMap<String, Mutex<SplitOutput>>>;

/// Split one input file (possibly in parallel with others)
fn split_one(outputs: &Splitter, prefix: &Regex, unzip: &mut Child) {
    let mut output = unzip.stdout.as_mut().unwrap();
    let mut reader = csv::Reader::from_reader(&mut output).has_headers(false);
    for row in reader.records() {
        let row = row.unwrap();
        let iprefix = prefix.captures(&row[0]).expect("Doesn't match").at(1).unwrap();
        /*
         * First try to get an already existing opened file. If it is not there (rare),
         * drop the read lock, acquire a new write one and check again (someone might have
         * created it at the time we didn't hold the lock) and possibly create it.
         */
        let created: bool;
        {
            if let Some(output) = outputs.read().unwrap().get(iprefix) {
                created = true;
                output.lock().unwrap().process(&row);
            } else {
                created = false;
            }
        }
        if !created {
            let mut wlock = outputs.write().unwrap();
            wlock.entry(String::from(iprefix)).or_insert_with(|| Mutex::new(SplitOutput::new(iprefix))).lock().unwrap().process(&row);
        }
    }
}

/// Perform the splitting phase, returning set of the file prefixes it has been sorted into.
fn split(pool: &scoped_pool::Pool) -> HashSet<String> {
    let outputs: Splitter = RwLock::new(HashMap::new());
    let prefix = Regex::new(r"^(.[^.:]?)").unwrap();
    pool.scoped(|scope|{
        for arg in std::env::args().skip(1) {
            let outputs = &outputs;
            let prefix = &prefix;
            scope.execute(move || {
                let mut unzip = Command::new("/usr/bin/pbzip2").arg("-dc").arg(arg).stdout(Stdio::piped()).spawn().expect("Failed to start unzip");
                split_one(outputs, prefix, &mut unzip);
                unzip.wait().unwrap();
            });
        }
    });
    outputs.into_inner().unwrap().into_iter().map(|(k, _)| k).collect()
}

fn main() {
    let pool = scoped_pool::Pool::new(6);
    split(&pool);
}

/*!
 * This takes several compressed CSV inputs in the form:
 *
 * ```text
 * 1.2.3.4,2016-02-02,3,ssh
 * 1.2.3.4,2016-12-02,1,telnet
 * ...
 * ```
 *
 * It produces (on stdout) pairs of IP JSON, describing aggregated events from the IP addresses.
 * There's at most one line per IP address.
 *
 * The lines look like this:
 *
 * ```text
 * 1.2.3.4  {"telnet":{"2016:12:01":1},"ssh":{"2016-02-02":3}}
 * ```
 *
 * It does so by first splitting it into multiple files (by the string prefix of the IP address, to
 * load balance it a bit), sorting each file and then aggregatting consequitive items.
 */

extern crate csv;
extern crate regex;
extern crate scoped_pool;
extern crate serde_json;
extern crate rustc_serialize;
extern crate fnv;

use std::process::*;
use std::sync::*;
use std::io::{Write,BufWriter,BufReader};
use std::net::IpAddr;
use std::fs::remove_file;

use regex::Regex;
use fnv::{FnvHashMap, FnvHashSet};

/**
 * This is the inner part of SplitOutput.
 *
 * It holds the actual command that gets waited on and implements the
 * Write trait. This is just an implementation trick to make it possible
 * to wrap something inside BufWriter.
 */
struct SplitOutputInner {
    child: Child
}

impl SplitOutputInner {
    /// Create the new compressor with the given file prefix
    fn new(name: &str) -> SplitOutputInner {
        SplitOutputInner { child: Command::new("/bin/sh").arg("-c").arg(format!("gzip -1 >{}.csv.gz", name)).stdin(Stdio::piped()).spawn().expect("Failed to start gzip") }
    }
}

impl Drop for SplitOutputInner {
    /// Make sure all is written and the command terminated before we exit
    fn drop(&mut self) {
        self.child.wait().expect("Output wait error");
    }
}

/// A write implementation, so we can wrap this into the buffer writer.
impl Write for SplitOutputInner {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.child.stdin.as_mut().unwrap().write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.child.stdin.as_mut().unwrap().flush()
    }
}

/**
 * Object representing output writer into a file. It compresses
 * the data as it goes.
 */
struct SplitOutput {
    output: BufWriter<SplitOutputInner>
}

impl SplitOutput {
    /**
     * Create a new SplitOutput. It openes the compressor and stores its output. The name is the
     * prefix of the file.
     */
    fn new(name: &str) -> SplitOutput {
        SplitOutput { output: BufWriter::with_capacity(2048, SplitOutputInner::new(name)) }
    }
    /// Write some data into the file.
    fn process(&mut self, data: &[String]) {
        writeln!(self.output, "{},{},{},{}", data[0], data[1], data[2], data[3]).expect("Write error");
    }
}

/// Bunch of outputs to store into.
type Splitter = RwLock<FnvHashMap<String, Mutex<SplitOutput>>>;

/// Split one input file (possibly in parallel with others)
fn split_one(outputs: &Splitter, prefix: &Regex, unzip: &mut Child) {
    let output = unzip.stdout.as_mut().unwrap();
    let mut reader = csv::Reader::from_reader(BufReader::with_capacity(4 * 1024 * 1024, output)).has_headers(false);
    for row in reader.records() {
        let row = row.unwrap();
        let iprefix = prefix.captures(&row[0]).expect("Doesn't match").get(1).unwrap().as_str();
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
fn split(pool: &scoped_pool::Pool) -> FnvHashSet<String> {
    let outputs: Splitter = RwLock::new(FnvHashMap::default());
    let prefix = Regex::new(r"^(.[^.:]?)").unwrap();
    pool.scoped(|scope| {
        for arg in std::env::args().skip(1) {
            let outputs = &outputs;
            let prefix = &prefix;
            scope.execute(move || {
                let cmd = if arg.ends_with(".bz2") {
                    "bzip2 -dc"
                } else {
                    "cat"
                };
                let mut unzip = Command::new("/bin/sh").arg("-c").arg(format!("{} <\"{}\" | (bigbuffer 128 || cat)", cmd, arg)).stdout(Stdio::piped()).spawn().expect("Failed to start unzip");
                split_one(outputs, prefix, &mut unzip);
                unzip.wait().expect("Failed to wait for unzip");
            });
        }
    });
    outputs.into_inner().unwrap().into_iter().map(|(k, _)| k).collect()
}

/// A record in the CSV input
#[derive(RustcDecodable)]
struct Record {
    ip: String,
    date: String,
    cnt: u32,
    kind: String
}

/// The summed up incidents per IP address.
type ResultSum = FnvHashMap<String, FnvHashMap<String, u32>>;

/**
 * A buffer that'll lock when writing the output to stdout (since there'll be many in multiple
 * threads).
 */
struct MultiBuf {
    buffer: Vec<String>
}

impl MultiBuf {
    fn new() -> MultiBuf {
        MultiBuf { buffer: Vec::with_capacity(1024) }
    }
    fn flush(&mut self) {
        let stdout = std::io::stdout();
        let lock = stdout.lock();
        let mut writer = BufWriter::with_capacity(1024 * 1024, lock);
        for s in self.buffer.drain(0..) {
            writeln!(writer, "{}", s).unwrap();
        }
    }
    fn write(&mut self, data: String) {
        if self.buffer.len() == self.buffer.capacity() {
            self.flush();
        }
        self.buffer.push(data);
    }
}

impl Drop for MultiBuf {
    fn drop(&mut self) {
        self.flush();
    }
}

/// If there's something for the previous IP, output it as IP JSON pair and reset the result
fn json_output(buf: &mut MultiBuf, sum: &mut ResultSum, last: &mut Option<IpAddr>) {
    if let Some(ip) = *last {
        buf.write(format!("{}\t{}", ip, serde_json::to_string(&sum).unwrap()));
        *sum = FnvHashMap::default();
    }
}

/// Is this IP allowed? Disallows bunch of private, loopback, multicast and other strange addresses
fn ip_allow(ip: &IpAddr) -> bool {
    // We would love to use ip.is_global, but that one is marked as unstable :-(
    match *ip {
        IpAddr::V4(ref a) => !(a.is_private() || a.is_loopback() || a.is_broadcast() || a.is_multicast() || a.is_unspecified() || a.is_documentation() || a.is_link_local()),
        IpAddr::V6(ref a) => !(a.is_unspecified() || a.is_loopback() || a.is_multicast())
    }
}

/**
 * Go through the sorted output from the child, aggregate the things belonging to the same IP and
 * output the JSONs.
 */
fn aggregate(sort: &mut Child) {
    let mut last: Option<IpAddr> = None;
    let output = sort.stdout.as_mut().unwrap();
    let mut reader = csv::Reader::from_reader(BufReader::new(output)).has_headers(false);
    let mut sum: ResultSum = FnvHashMap::default();
    let mut buf = MultiBuf::new();
    for row in reader.decode() {
        let row: Record = row.unwrap();
        let ip: IpAddr = row.ip.parse().unwrap();
        if !ip_allow(&ip) {
            continue;
        }
        if Some(ip) != last {
            json_output(&mut buf, &mut sum, &mut last);
        }
        last = Some(ip);
        *sum.entry(row.kind).or_insert_with(FnvHashMap::default).entry(row.date).or_insert(0) += row.cnt;
    }
    json_output(&mut buf, &mut sum, &mut last);
}

/**
 * Go through the content of all the files with given prefixes, process them
 * and produce aggregated JSONs.
 */
fn jsonize(pool: &scoped_pool::Pool, prefixes: FnvHashSet<String>) {
    pool.scoped(|scope| {
        for mut prefix in prefixes.into_iter() {
            scope.execute(move || {
                prefix.push_str(".csv.gz");
                let mut sort = Command::new("/bin/sh").arg("-c").arg(format!("gunzip -cd {} | sort -S 2G -T .", prefix)).env("LC_ALL", "C").stdout(Stdio::piped()).spawn().expect("Failed to run sort");
                aggregate(&mut sort);
                sort.wait().expect("Failed to wait for sort");
                remove_file(prefix).expect("Failed to remove gzip temporary");
            });
        }
    });
}

fn main() {
    let pool = scoped_pool::Pool::new(6);
    let prefixes = split(&pool);
    jsonize(&pool, prefixes);
}

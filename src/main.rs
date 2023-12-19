use rand::prelude::*;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::mpsc::{self, Receiver, SendError};
use std::thread;

const NUM_WORKERS: usize = 8;
const HASH_LENGTH_BITS: usize = 64;
const HASH_LENGTH_BYTES: usize = HASH_LENGTH_BITS / 8;

type Bytes = [u8; HASH_LENGTH_BYTES];

fn sha256_trunc(msg: String) -> Bytes {
    let hasher = Sha256::digest(msg.as_bytes());
    let mut hash = [0; HASH_LENGTH_BYTES];
    hash.copy_from_slice(&hasher[..HASH_LENGTH_BYTES]);
    hash
}

fn hash_to_msg(hash: Bytes) -> String {
    // convert to hex string
    format!("hello {}", hex::encode(hash))
}

fn is_distinguished(x: Bytes) -> bool {
    // starts with 0x00 0x00
    x[0] == 0 && x[1] == 0
}

fn pollard_next(hash: Bytes) -> Bytes {
    sha256_trunc(hash_to_msg(hash))
}

fn trail() -> (Bytes, Bytes) {
    let mut rng = rand::thread_rng();

    let mut start: Bytes = [0; HASH_LENGTH_BYTES];
    rng.fill_bytes(&mut start);

    let mut point = start.clone();

    while !is_distinguished(point) {
        point = pollard_next(point);
    }

    (start, point)
}

fn trail_worker(tx: mpsc::Sender<(Bytes, Bytes)>) {
    loop {
        // send until channel is closed
        if let Err(SendError(_)) = tx.send(trail()) {
            break;
        }
    }
}

fn orchestrate_workers(rx: Receiver<(Bytes, Bytes)>) -> (Bytes, Bytes) {
    // lookup table - Bytes to Bytes
    let mut lookup: HashMap<Bytes, Bytes> = HashMap::new();

    while let Ok((start, end)) = rx.recv() {
        if lookup.contains_key(&end) {
            let existing_start = lookup.get(&end).unwrap().clone();
            println!("found cycle: {} entries in lookup table", lookup.len());
            return (existing_start, start);
        } else {
            // add to lookup table
            lookup.insert(end, start);
        }
    }
    panic!("channel closed before cycle was found")
}

fn main() {
    let (tx, rx) = mpsc::channel();

    // start workers
    for _ in 0..NUM_WORKERS {
        let tx = tx.clone();
        thread::spawn(move || trail_worker(tx));
    }

    // find trails
    let (mut trail_a, mut trail_b) = orchestrate_workers(rx);

    // kill workers
    drop(tx);

    // find the point where the two trails meet

    let mut lookup: HashMap<Bytes, Bytes> = HashMap::new();

    while !is_distinguished(trail_a) {
        let prev = trail_a;
        trail_a = pollard_next(trail_a);
        lookup.insert(trail_a, prev);
    }

    let mut prev = trail_b;

    while !lookup.contains_key(&trail_b) {
        prev = trail_b;
        trail_b = pollard_next(trail_b);
    }

    let msg_a = hash_to_msg(prev);
    let msg_b = hash_to_msg(lookup[&trail_b]);

    println!(
        "sha256_{}({}) => {}",
        HASH_LENGTH_BITS,
        msg_a,
        hex::encode(sha256_trunc(msg_a.clone()))
    );
    println!(
        "sha256_{}({}) => {}",
        HASH_LENGTH_BITS,
        msg_b,
        hex::encode(sha256_trunc(msg_b.clone()))
    );
}

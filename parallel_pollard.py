# David Buchanan's reference implementation
# https://www.da.vidbuchanan.co.uk/blog/colliding-secure-hashes.html

import hashlib
import os
from multiprocessing import Queue, Process
from typing import Tuple

NUM_WORKERS = 8
HASH_LENGTH_BITS = 32
HASH_LENGH_BYTES = HASH_LENGTH_BITS // 8


def sha256_trunc(data: bytes) -> bytes:
    h = hashlib.sha256(data).digest()
    return h[:HASH_LENGH_BYTES]


def hash_to_msg(h: bytes) -> bytes:
    return f"hello {h.hex()}".encode()


def pollard_next(h: bytes) -> bytes:
    return sha256_trunc(hash_to_msg(h))


def is_distinguished(h: bytes) -> bool:
    return h.startswith(b"\x00\x00")


def build_trail() -> Tuple[bytes, bytes]:
    trail_start = sha256_trunc(os.urandom(16))
    point = trail_start
    while not is_distinguished(point):
        point = pollard_next(point)
    return trail_start, point


def trail_worker(q: Queue):
    while True:
        q.put(build_trail())


if __name__ == "__main__":
    q = Queue()
    lookup = {}
    workers = [Process(target=trail_worker, args=(q,)) for _ in range(NUM_WORKERS)]
    for w in workers:
        w.start()  # start the workers

    while True:
        start, end = q.get()
        if end in lookup:
            print(f"Found colliding trails! ({len(lookup)} trails total)")
            break
        lookup[end] = start

    for w in workers:
        w.kill()  # we're done with them now!

    # find the point where the two trails meet
    # (naively - time/space tradeoffs are possible here)
    lookup2 = {}
    point = lookup[end]
    while not is_distinguished(point):
        point, prev = pollard_next(point), point
        lookup2[point] = prev

    point = start
    while point not in lookup2:
        point, prev = pollard_next(point), point

    msg_a = hash_to_msg(prev)
    msg_b = hash_to_msg(lookup2[point])
    print(f"sha256_{HASH_LENGTH_BITS}({msg_a}) => {sha256_trunc(msg_a).hex()}")
    print(f"sha256_{HASH_LENGTH_BITS}({msg_b}) => {sha256_trunc(msg_b).hex()}")

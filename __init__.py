import time

import gevent
import gevent.queue
from gevent import Greenlet
from gevent.pool import Pool
from gevent import monkey; monkey.patch_all(thread=False)


def gcd(a, b):
    assert a >= b
    if b == 0:
        return a
    else:
        return gcd(b, a % b)


def factorial(x):
    assert x >= 0
    if x == 1 or x == 0:
        return 1
    else:
        return x * factorial(x - 1)


def new_gcd(a, b):
    assert a >= b
    return a if b == 0 else new_gcd(b, a % b)

m = gevent.queue.Queue()

def infinite_loop():
    while True:
        gevent.sleep(0)
        print("blocked")
        s = m.get()
        print(s)
        continue

def bytes_split(split_bytes, num_seg, idx, t):
    """
        split the bytes into segments of same length, and return the segment of idx

        :param bytes split_bytes: the bytes to be split
        :param int num_seg: the number of segments
        :param int idx: the segment of idx to be returned
    """
    seg_len = int(len(split_bytes) / num_seg)
    if len(split_bytes) % num_seg == 0 or idx < num_seg - 1:
        t.kill()
        return split_bytes[idx * seg_len: (idx + 1) * seg_len]
    else:
        t.kill()
        return split_bytes[seg_len * (num_seg - 1):]


if __name__ == '__main__':
    a = b'kfjlsjdkljfisdjfiefsjdifjioejflk;sdjfisdf'
    infinite_loop_thread = gevent.spawn(infinite_loop)
    pool = [gevent.spawn(bytes_split, a, 2, i, infinite_loop_thread) for i in range(2)]

    # gevent.joinall(pool)

    for p in pool:
        print(f"{p.get()}")

    infinite_loop_thread.kill()
    print("finished")

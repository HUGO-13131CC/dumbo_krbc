import gevent
from gevent import monkey; monkey.patch_all(thread=False)

from datetime import datetime
import time
from collections import defaultdict
from crypto.ecdsa.ecdsa import ecdsa_vrfy, ecdsa_sign
from honeybadgerbft.core.reliablebroadcast import merkleTree, getMerkleBranch, merkleVerify
from honeybadgerbft.core.reliablebroadcast import encode, decode
import hashlib, pickle


def hash(x):
    return hashlib.sha256(pickle.dumps(x)).digest()


def bytes_split(split_bytes, num_seg):
    """
    split the bytes into segments of same length

    :param bytes split_bytes: the bytes to be split
    :param int num_seg: the number of segments
    """
    seg_len = int(len(split_bytes) / num_seg)
    if len(split_bytes) % num_seg == 0:
        ret = [split_bytes[i: i+seg_len] for i in range(0, len(split_bytes), seg_len)]
    else:
        ret = [split_bytes[i: i+seg_len] for i in range(0, len(split_bytes) - 2 * seg_len, seg_len)]
        ret.append(split_bytes[seg_len * len(ret):])

    return ret


def provablereliablebroadcast(sid, pid, N, f,  PK2s, SK2, leader, input, receive, send, logger=None):
    """Reliable broadcastdef hash(x):
    return hashlib.sha256(pickle.dumps(x)).digest()

    :param int pid: ``0 <= pid < N``
    :param int N:  at least 3
    :param int f: fault tolerance, ``N >= 3f + 1``

    :param list PK2s: an array of ``coincurve.PublicKey'', i.e., N public keys of ECDSA for all parties
    :param PublicKey SK2: ``coincurve.PrivateKey'', i.e., secret key of ECDSA
    :param int leader: ``0 <= leader < N``
    :param input: if ``pid == leader``, then :func:`input()` is called
        to wait for the input value
    :param receive: :func:`receive()` blocks until a message is
        received; message is of the form::

            (i, (tag, ...)) = receive()

        where ``tag`` is one of ``{"VAL", "ECHO", "READY"}``
    :param send: sends (without blocking) a message to a designed
        recipient ``send(i, (tag, ...))``

    :return str: ``m`` after receiving :math:`2f+1` ``READY`` messages
        and :math:`N-2f` ``ECHO`` messages

        .. important:: **Messages**

            ``VAL( roothash, branch[i], stripe[i] )``
                sent from ``leader`` to each other party
            ``ECHO( roothash, branch[i], stripe[i] )``
                sent after receiving ``VAL`` message
            ``READY( roothash, sigma )``
                sent after receiving :math:`N-f` ``ECHO`` messages
                or after receiving :math:`f+1` ``READY`` messages

    .. todo::
        **Accountability**

        A large computational expense occurs when attempting to
        decode the value from erasure codes, and recomputing to check it
        is formed correctly. By transmitting a signature along with
        ``VAL`` and ``ECHO``, we can ensure that if the value is decoded
        but not necessarily reconstructed, then evidence incriminates
        the leader.

    """

    #assert N >= 3*f + 1
    #assert f >= 0
    #assert 0 <= leader < N
    #assert 0 <= pid < N

    #print("RBC starts...")

    K               = N - 2 * f  # Need this many to reconstruct. (# noqa: E221)
    EchoThreshold   = N - f      # Wait for this many ECHO to send READY. (# noqa: E221)
    ReadyThreshold  = f + 1      # Wait for this many READY to amplify READY. (# noqa: E221)
    OutputThreshold = N - f      # Wait for this many READY to output

    NUM_OF_SEG = 3  # the number of segments to broadcast parallely
    # NOTE: The above thresholds  are chosen to minimize the size
    # of the erasure coding stripes, i.e. to maximize K.
    # The following alternative thresholds are more canonical
    # (e.g., in Bracha '86) and require larger stripes, but must wait
    # for fewer nodes to respond
    #   EchoThreshold = ceil((N + f + 1.)/2)
    #   K = EchoThreshold - f

    def broadcast(o):
        send(-1, o)

    start = time.time()

    if pid == leader:
        # The leader erasure encodes the input, sending one strip to each participant
        # print("block to wait for RBC input")
        m = input()  # block until an input is received
        # print(m)
        # assert isinstance(m, (str, bytes))
        # print('Input received: %d bytes' % (len(m),))

        ''' split the m into N segments '''
        m_segments = bytes_split(m, NUM_OF_SEG)

        assert NUM_OF_SEG == len(m_segments)

        for idx, _m in enumerate(m_segments):
            stripes = encode(K, N, _m)
            mt = merkleTree(stripes)  # full binary tree
            roothash = mt[1]
            for i in range(N):
                branch = getMerkleBranch(i, mt)
                """ Add an idx to notify the segment of the whole msg """
                send(i, ('VAL', roothash, branch, stripes[i], idx))
                # print(f"send {idx}")
        # print("encoding time: " + str(end - start))

    # TODO: filter policy: if leader, discard all messages until sending VAL
    # To extend the params from single to multiple
    # fromLeader = None
    fromLeader = [None for _ in range(NUM_OF_SEG)]
    # stripes = defaultdict(lambda: [None for _ in range(N)])
    stripes = [defaultdict(lambda: [None for _ in range(N)]) for _ in range(NUM_OF_SEG)]
    # echoCounter = defaultdict(lambda: 0)
    echoCounter = [defaultdict(lambda: 0) for _ in range(NUM_OF_SEG)]
    # echoSenders = set()  # Peers that have sent us ECHO messages
    echoSenders = [set() for _ in range(NUM_OF_SEG)]
    # ready = defaultdict(set)
    ready = [defaultdict(set) for _ in range(NUM_OF_SEG)]
    # readySent = False
    readySent = [False for _ in range(NUM_OF_SEG)]
    # readySenders = set()  # Peers that have sent us READY messages
    readySenders = [set() for _ in range(NUM_OF_SEG)]
    # readySigShares = defaultdict(lambda: None)
    readySigShares = [defaultdict(lambda: None) for _ in range(NUM_OF_SEG)]
    finishBroadcast = [0 for _ in range(NUM_OF_SEG)]
    values = [None for _ in range(NUM_OF_SEG)]
    proofs = [None for _ in range(NUM_OF_SEG)]

    SIGMA = ((0, "1"), (1, "1"), (2, "1"), (3, "1"),
             (4, "1"), (5, "1"), (6, "1"), (7, "1"),
             (8, "1"), (9, "1"))

    def decode_output(roothash, idx):
        # Rebuild the merkle tree to guarantee decoding is correct
        m = decode(K, N, stripes[idx][roothash])
        _stripes = encode(K, N, m)
        _mt = merkleTree(_stripes)
        _roothash = _mt[1]
        # TODO: Accountability: If this fails, incriminate leader
        assert _roothash == roothash
        return m

    msg_pool = [[] for _ in range(NUM_OF_SEG)]

    def loop_recv(_idx):
        # print("loop_recv")
        while True:  # main receive loop
            # gevent.sleep(0)
            while len(msg_pool[_idx]) == 0:
                gevent.sleep(0)
                continue
            (sender, msg) = msg_pool[_idx].pop()
            if msg[0] == 'VAL':
                # Validation
                (_, roothash, branch, stripe, idx) = msg
                if fromLeader[idx] is None:
                    if sender != leader:
                        print("VAL message from other than leader:", sender)
                        continue
                    try:
                        assert merkleVerify(N, stripe, roothash, branch, pid)
                    except Exception as e:
                        print("Failed to validate VAL message:", e)
                        continue
                    # Update
                    fromLeader[idx] = roothash
                    broadcast(('ECHO', roothash, branch, stripe, idx))

            elif msg[0] == 'ECHO':
                (_, roothash, branch, stripe, idx) = msg
                # Validation
                if roothash in stripes[idx] and stripes[idx][roothash][sender] is not None \
                   or sender in echoSenders[idx]:
                    continue
                try:
                    assert merkleVerify(N, stripe, roothash, branch, sender)
                except AssertionError as e:
                    print("Failed to validate ECHO message:", e)
                    continue

                # Update
                stripes[idx][roothash][sender] = stripe
                echoSenders[idx].add(sender)
                echoCounter[idx][roothash] += 1

                if echoCounter[idx][roothash] >= EchoThreshold and not readySent[idx]:
                    readySent[idx] = True
                    send(-1, ('READY', roothash, None, idx))

            elif msg[0] == 'READY':
                (_, roothash, sig, idx) = msg
                # Validation
                if sender in ready[idx][roothash] or sender in readySenders[idx]:
                    print(f"Redundant READY {idx}")
                    continue

                # Update
                ready[idx][roothash].add(sender)
                readySenders[idx].add(sender)
                readySigShares[idx][sender] = sig

                # Amplify ready messages
                if len(ready[idx][roothash]) >= ReadyThreshold and not readySent[idx]:
                    readySent[idx] = True
                    # digest = hash((sid, roothash))
                    # sig = ecdsa_sign(SK2, digest)
                    send(-1, ('READY', roothash, None, idx))
                    # print(f"Ready {idx}")

                if len(ready[idx][roothash]) >= OutputThreshold and echoCounter[idx][roothash] >= K:
                    # sigmas = tuple(list(readySigShares.items())[:OutputThreshold])
                    value = decode_output(roothash, idx)
                    proof = (sid, roothash, SIGMA)
                    # print("RBC finished for leader", leader)
                    values[idx] = value
                    proofs[idx] = proof
                    finishBroadcast[idx] = 1
                    break

    pool = [gevent.spawn(loop_recv, i) for i in range(NUM_OF_SEG)]

    while sum(finishBroadcast) < NUM_OF_SEG:
        # gevent.sleep(0)
        # print("blocked")
        sender, msg = receive()
        # print(msg[-1])
        msg_pool[msg[-1]].append((sender, msg))

    end = time.time()
    if logger != None:
        logger.info("ABA %d completes in %f seconds" % (leader, end - start))

    """ join the values """
    ret_value = values[0]
    for v in values[1:]:
        ret_value += v

    """ join the proofs """
    roothash = proofs[0][1]
    for p in proofs[1:]:
        roothash += p[1]

    ret_proof = (sid, roothash, SIGMA)

    for p in pool:
        p.kill()

    return ret_value, ret_proof
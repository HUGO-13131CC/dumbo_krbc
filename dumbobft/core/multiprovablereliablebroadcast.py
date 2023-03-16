import gevent
from gevent import monkey; monkey.patch_all(thread=False)

import time
import gevent
from gevent.queue import Queue
from collections import defaultdict
from crypto.ecdsa.ecdsa import ecdsa_vrfy, ecdsa_sign
from honeybadgerbft.core.reliablebroadcast import merkleTree, getMerkleBranch, merkleVerify
from honeybadgerbft.core.reliablebroadcast import encode, decode
import hashlib, pickle

NUM_OF_SEG = 3  # The number of segment
SIGMA = ((0, "1"), (1, "1"), (2, "1"),
         (3, "1"), (4, "1"), (5, "1"),
         (6, "1"), (7, "1"), (8, "1"), (9, "1"))


def bytes_split(split_bytes, num_seg, idx):
    """
        split the bytes into segments of same length, and return the segment of idx

        :param bytes split_bytes: the bytes to be split
        :param int num_seg: the number of segments
        :param int idx: the segment of idx to be returned
    """
    seg_len = int(len(split_bytes) / num_seg)
    if len(split_bytes) % num_seg == 0 or idx < num_seg - 1:
        return split_bytes[idx * seg_len: (idx + 1) * seg_len]
    else:
        return split_bytes[seg_len * (num_seg - 1):]


def hash(x):
    return hashlib.sha256(pickle.dumps(x)).digest()


def provablereliablebroadcast_for_leader(sid, pid, N, f,  PK2s, SK2, leader, input, receive, send, num_of_seg, logger=None):
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

    # NUM_OF_SEG = 3  # the number of segments to broadcast parallely
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


    # The leader erasure encodes the input, sending one strip to each participant
    # print("block to wait for RBC input")
    m = input()  # block until an input is received
    # print(m)
    # assert isinstance(m, (str, bytes))
    # print('Input received: %d bytes' % (len(m),))

    ''' split the m into N segments '''
    def parallel_val_send(m, idx):
        m_segment = bytes_split(m, NUM_OF_SEG, idx)

        stripes = encode(K, N, m_segment)
        mt = merkleTree(stripes)  # full binary tree
        roothash = mt[1]
        for i in range(N):
            branch = getMerkleBranch(i, mt)
            """ Add an idx to notify the segment of the whole msg """
            send(i, ('VAL', roothash, branch, stripes[i], idx))
            # print(f"Leader send {idx}")
    # print("encoding time: " + str(end - start))
    parallel_val_send_thread = [gevent.spawn(parallel_val_send, m, i) for i in range(num_of_seg)]

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


    def decode_output(roothash, idx):
        # Rebuild the merkle tree to guarantee decoding is correct
        m = decode(K, N, stripes[idx][roothash])
        _stripes = encode(K, N, m)
        _mt = merkleTree(_stripes)
        _roothash = _mt[1]
        # TODO: Accountability: If this fails, incriminate leader
        assert _roothash == roothash
        return m

    # msg_pool = [[] for _ in range(NUM_OF_SEG)]
    msg_pool = [Queue() for _ in range(NUM_OF_SEG)]

    def outer_listener():
        while sum(finishBroadcast) < NUM_OF_SEG:
            # print("Leader blocked")
            sender, msg = receive()
            # print(f"Leader msg pool filled at {msg[-1]}")
            msg_pool[msg[-1]].put_nowait((sender, msg))
            gevent.sleep(0)

    def loop_recv(_idx, t):
        # print("Leader loop_recv")
        while True:  # main receive loop
            (sender, msg) = msg_pool[_idx].get()
            if msg[0] == 'VAL':
                # Validation
                (_, roothash, branch, stripe, idx) = msg
                if fromLeader[idx] is None:
                    if sender != leader:
                        # print("VAL message from other than leader:", sender)
                        continue
                    try:
                        assert merkleVerify(N, stripe, roothash, branch, pid)
                    except Exception as e:
                        # print("Failed to validate VAL message:", e)
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
                    # print("Failed to validate ECHO message:", e)
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
                    # print(f"Redundant READY {idx}")
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
                    # print(f"Leader{pid}-{idx} broadcast finished")
                    if sum(finishBroadcast) == num_of_seg:
                        t.kill()
                        # print("outer thread has been killed")
                    return 1
            gevent.sleep(0)

    outer_listener_thread = gevent.spawn(outer_listener)
    pool = [gevent.spawn(loop_recv, i, outer_listener_thread) for i in range(NUM_OF_SEG)]

    for p in pool:
        _ = p.get()
        # print(_)
        p.kill()

    end = time.time()
    if logger != None:
        logger.info("ABA %d completes in %f seconds" % (leader, end - start))

    """ join the values """
    # print("join the values")
    ret_value = values[0]
    for v in values[1:]:
        ret_value += v

    """ join the proofs """
    # print("join the proofs")
    roothash = proofs[0][1]
    for p in proofs[1:]:
        roothash += p[1]

    for s in parallel_val_send_thread:
        s.kill()

    proof = (sid, roothash, SIGMA)

    return ret_value, proof


def provablereliablebroadcast_for_receiver(sid, pid, N, f, PK2s, SK2, leader, input, receive, send, num_of_seg,
                                         logger=None):
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
    :param idx: the segment mark

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

    # assert N >= 3*f + 1
    # assert f >= 0
    # assert 0 <= leader < N
    # assert 0 <= pid < N

    # print("RBC starts...")

    K = N - 2 * f  # Need this many to reconstruct. (# noqa: E221)
    EchoThreshold = N - f  # Wait for this many ECHO to send READY. (# noqa: E221)
    ReadyThreshold = f + 1  # Wait for this many READY to amplify READY. (# noqa: E221)
    OutputThreshold = N - f  # Wait for this many READY to output

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
    # print(f"pid-{pid}, idx-{idx}, leader-{leader}")

    # The leader erasure encodes the input, sending one strip to each participant
    # print("block to wait for RBC input")
    # m = input()  # block until an input is received
    # # print("RBC input received: ", m[:30])
    # # assert isinstance(m, (str, bytes))
    # # print('Input received: %d bytes' % (len(m),))
    # m = bytes_split(m, num_of_seg, idx)
    # stripes = encode(K, N, m)
    # mt = merkleTree(stripes)  # full binary tree
    # roothash = mt[1]
    # for i in range(N):
    #     branch = getMerkleBranch(i, mt)
    #     send(i, ('VAL', roothash, branch, stripes[i], idx))
    #     print(f"{pid} send {pid}-{idx}")
    # print("encoding time: " + str(end - start))

    # TODO: filter policy: if leader, discard all messages until sending VAL

    fromLeader = [None for _ in range(num_of_seg)]
    stripes = [defaultdict(lambda: [None for _ in range(N)]) for _ in range(num_of_seg)]
    echoCounter = [defaultdict(lambda: 0) for _ in range(num_of_seg)]
    echoSenders = [set() for _ in range(num_of_seg)]  # Peers that have sent us ECHO messages
    ready = [defaultdict(set) for _ in range(num_of_seg)]
    readySent = [False for _ in range(num_of_seg)]
    readySenders = [set() for _ in range(num_of_seg)]  # Peers that have sent us READY messages
    readySigShares = [defaultdict(lambda: None) for _ in range(num_of_seg)]
    finishBroadcast = [0 for _ in range(num_of_seg)]
    values = [None for _ in range(num_of_seg)]
    roothashes = [None for _ in range(num_of_seg)]

    def decode_output(roothash, i):
        # Rebuild the merkle tree to guarantee decoding is correct
        m = decode(K, N, stripes[i][roothash])
        _stripes = encode(K, N, m)
        _mt = merkleTree(_stripes)
        _roothash = _mt[1]
        # TODO: Accountability: If this fails, incriminate leader
        assert _roothash == roothash
        return m

    while True:  # main receive loop
        gevent.sleep(0)
        sender, msg = receive()
        _i = msg[-1]
        if msg[0] == 'VAL' and fromLeader[_i] is None:
            # print(f"{pid} receive VAL from {sender}")
            # Validation
            (_, roothash, branch, stripe, i) = msg
            if sender != leader:
                print("VAL message from other than leader:", sender)
                continue
            try:
                assert merkleVerify(N, stripe, roothash, branch, pid)
            except Exception as e:
                print("Failed to validate VAL message:", e)
                continue
            # Update
            fromLeader[i] = roothash
            broadcast(('ECHO', roothash, branch, stripe, i))
            # print(f"{pid} echo {sender}-{i}")

        elif msg[0] == 'ECHO':
            # print(f"{pid} receive ECHO from {sender}")
            (_, roothash, branch, stripe, i) = msg
            # Validation
            if roothash in stripes[i] and stripes[i][roothash][sender] is not None \
                    or sender in echoSenders[i]:
                # print(f"Redundant ECHO {sender in echoSenders[i]}")
                continue
            try:
                assert merkleVerify(N, stripe, roothash, branch, sender)
            except AssertionError as e:
                print("Failed to validate ECHO message:", e)
                continue

            # Update
            stripes[i][roothash][sender] = stripe
            echoSenders[i].add(sender)
            echoCounter[i][roothash] += 1

            if echoCounter[i][roothash] >= EchoThreshold and not readySent[i]:
                readySent[i] = True
                # digest = hash((sid, roothash))
                # sig = ecdsa_sign(SK2, digest)       # signature
                send(-1, ('READY', roothash, None, i))
                # print(f"{pid} ready {sender}-{i}")

            # if len(ready[roothash]) >= OutputThreshold and echoCounter[roothash] >= K:
            #    return decode_output(roothash)

        elif msg[0] == 'READY':
            # print(f"{pid} receive READY from {sender}")
            (_, roothash, sig, i) = msg
            # Validation
            if sender in ready[i][roothash] or sender in readySenders[i]:
                print(f"Redundant READY {sender in ready[i][roothash]}, {sender in readySenders[i]}")
                continue
            # try:
            #     digest = hash((sid, roothash))
            #     assert ecdsa_vrfy(PK2s[sender], digest, sig)
            # except AssertionError:
            #     print("Signature share failed in PRBC!", (sid, pid, sender, msg))
            #     continue

            # Update
            ready[i][roothash].add(sender)
            readySenders[i].add(sender)
            readySigShares[i][sender] = sig

            # Amplify ready messages
            if len(ready[i][roothash]) >= ReadyThreshold and not readySent[i]:
                readySent[i] = True
                # digest = hash((sid, roothash))
                # sig = ecdsa_sign(SK2, digest)
                send(-1, ('READY', roothash, None, i))
                # print(f"{pid} ready {sender}-{i}")

            if len(ready[i][roothash]) >= OutputThreshold and echoCounter[i][roothash] >= K:
                # sigmas = tuple(list(readySigShares.items())[:OutputThreshold])
                value = decode_output(roothash, i)
                values[i] = value
                roothashes[i] = roothash
                finishBroadcast[i] = 1

            if sum(finishBroadcast) == num_of_seg:
                # print("RBC finished for leader", leader)
                end = time.time()
                if logger != None:
                    logger.info("ABA %d completes in %f seconds" % (leader, end - start))
                # print(f"Output: {value[:30]}")
                value = b''
                r_roothash = b''
                for v, r in zip(values, roothashes):
                    value += v
                    r_roothash += r
                proof = (sid, r_roothash, SIGMA)
                # print(f"receiver {pid} broadcast finish!!!!!!")
                return value, proof


def multi_provable_reliable_broadcast(sid, pid, N, f, PK2s, SK2, leader, input, receive, send, logger=None):
    if pid == leader:
        return provablereliablebroadcast_for_leader(sid, pid, N, f, PK2s, SK2, leader, input, receive, send,
                                                      NUM_OF_SEG, logger)
    else:
        return provablereliablebroadcast_for_receiver(sid, pid, N, f, PK2s, SK2, leader, input, receive, send,
                                                      NUM_OF_SEG, logger)

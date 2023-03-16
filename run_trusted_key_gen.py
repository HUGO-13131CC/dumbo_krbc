from crypto.threshsig import boldyreva
from crypto.threshenc import tpke
from crypto.ecdsa import ecdsa
import pickle
import os


def trusted_key_gen(N=4, f=1, seed=None):

    # Generate threshold enc keys
    ePK, eSKs = tpke.dealer(N, f+1)

    # Generate threshold sig keys for coin (thld f+1)
    sPK, sSKs = boldyreva.dealer(N, f+1, seed=seed)

    # Generate threshold sig keys for cbc (thld n-f)
    sPK1, sSK1s = boldyreva.dealer(N, N-f, seed=seed)

    # Generate ECDSA sig keys
    sPK2s, sSK2s = ecdsa.pki(N)

    # Save all keys to files
    if f'keys-{N}' not in os.listdir(os.getcwd()):
        os.mkdir(os.getcwd() + f'/keys-{N}')

    # public key of (f+1, n) thld sig
    with open(os.getcwd() + f'/keys-{N}/' + 'sPK.key', 'wb') as fp:
        pickle.dump(sPK, fp)

    # public key of (n-f, n) thld sig
    with open(os.getcwd() + f'/keys-{N}/' + 'sPK1.key', 'wb') as fp:
        pickle.dump(sPK1, fp)

    # public key of (f+1, n) thld enc
    with open(os.getcwd() + f'/keys-{N}/' + 'ePK.key', 'wb') as fp:
        pickle.dump(ePK, fp)

    # public keys of ECDSA
    for i in range(N):
        with open(os.getcwd() + f'/keys-{N}/' + 'sPK2-' + str(i) + '.key', 'wb') as fp:
            pickle.dump(sPK2s[i].format(), fp)

    # private key of (f+1, n) thld sig
    for i in range(N):
        with open(os.getcwd() + f'/keys-{N}/' + 'sSK-' + str(i) + '.key', 'wb') as fp:
            pickle.dump(sSKs[i], fp)

    # private key of (n-f, n) thld sig
    for i in range(N):
        with open(os.getcwd() + f'/keys-{N}/' + 'sSK1-' + str(i) + '.key', 'wb') as fp:
            pickle.dump(sSK1s[i], fp)

    # private key of (f+1, n) thld enc
    for i in range(N):
        with open(os.getcwd() + f'/keys-{N}/' + 'eSK-' + str(i) + '.key', 'wb') as fp:
            pickle.dump(eSKs[i], fp)

    # private keys of ECDSA
    for i in range(N):
        with open(os.getcwd() + f'/keys-{N}/' + 'sSK2-' + str(i) + '.key', 'wb') as fp:
            pickle.dump(sSK2s[i].secret, fp)


if __name__ == '__main__':

    N = 64
    f = 21

    assert N >= 3 * f + 1

    trusted_key_gen(N, f)

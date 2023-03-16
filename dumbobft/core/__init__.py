import hashlib
import pickle


def hash(x):
    return hashlib.sha256(pickle.dumps(x)).digest()


if __name__ == '__main__':
    sid = 'sidA:0VACS0VACS-VABA'
    print(hash(sid))

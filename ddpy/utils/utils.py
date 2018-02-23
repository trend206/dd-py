import time, uuid, hashlib, platform, os


def get_challenge():
    '''Get the unique challenge UUID value for the Challenge header.'''
    challenge = str(uuid.uuid4())
    return challenge

def get_epoch_time():
    '''Get the epoch time (for the X-DTAS-Time header value.'''
    epoch_time = str(int(time.time()))
    return epoch_time


def get_system_hostname():
    '''Get the hostname of the system from which the script is being run'''
    hostname = platform.node()
    return hostname

def hash_file(filename):
    '''Calculate the SHA1 of a file'''
    h = hashlib.sha1()
    with open(filename, 'rb') as file:
        chunk = 0
        while chunk != b'':
            chunk = file.read(1024)
            h.update(chunk)
    return h.hexdigest()
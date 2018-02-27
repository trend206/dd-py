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


def calculate_checksum(self, headers):
    '''Calculate the header checksum used for authentication.'''
    # TODO: Extend method to handle use_checksum_calculating_order property == False
    if self.use_checksum_calculating_order == True:
        x_dtas_checksumcalculatingorder_list = headers['X-DTAS-ChecksumCalculatingOrder'].split(",")
        x_dtas_checksumcalculatingorder = ""
        for i in x_dtas_checksumcalculatingorder_list:
            x_dtas_checksumcalculatingorder += headers[i]
        x_dtas_checksum = hashlib.sha1((self.api_key + x_dtas_checksumcalculatingorder).encode('utf-8')).hexdigest()
        return x_dtas_checksum


def generate_meta_file_contents(orig_file_name: str, sample_file_sha1: str, archive_password: str, client_uuid: str, source_id:str, sample_file_exists:int = 1, sample_type:int = 0):
    str = "SampleType={}&ClientUUID={}&SourceID={}&SampleFileSHA1={}&SampleFileExist=1&OrigFileName={}&Archpassword={}" \
           .format(sample_type, client_uuid, source_id, sample_file_sha1, orig_file_name, archive_password)
    return str

import uuid, time, requests, hashlib, platform

eaders = {'Content-Type': 'application/json'}
from typing import List, Dict

class DDAN:

    def __init__(self, api_key: str, analyzer_ip, verify_cert:bool = False, protocol_veriosn:str = "1.5"):
        self.uuid = str(uuid.uuid4())
        self.api_key = api_key
        self.analyzer_ip = analyzer_ip
        self.protocol_version = protocol_veriosn
        self.use_checksum_calculating_order = True
        self.product_name = "TDA"
        self.client_hostname = self._get_system_hostname()
        self.source_id = "1"  # source_id of 1 == User submission
        self.source_name = "Python ddpy API Client"


        if not verify_cert:
                requests.packages.urllib3.disable_warnings()

        self._register()

    def test_connection(self):
        '''Issue a request to make sure that all settings are correct and the connection to Analyzer's API is good.'''
        url = "https://{analyzer_ip}/web_service/sample_upload/{service}".format(analyzer_ip=self.analyzer_ip,
                                                                                 service="test_connection")
        headers = {
            "X-DTAS-ProtocolVersion": self.protocol_version,
            "X-DTAS-Time": self.get_epoch_time(),
            "X-DTAS-Challenge": self.get_challenge(),
            "X-DTAS-ChecksumCalculatingOrder": "X-DTAS-ProtocolVersion,X-DTAS-Time,X-DTAS-Challenge"
        }
        # Calculate the header checksum and add it to the list of headers
        headers["X-DTAS-Checksum"] = self.calculate_checksum(headers)
        r = requests.get(url, verify=False, headers=headers)
        return r

    def get_challenge(self):
        '''Get the unique challenge UUID value for the Challenge header.'''
        challenge = str(uuid.uuid4())
        return challenge

    def get_epoch_time(self):
        '''Get the epoch time (for the X-DTAS-Time header value.'''
        epoch_time = str(int(time.time()))
        return epoch_time

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

    def get_black_lists(self, last_query_id="0"):
        '''Issue a request to retrieve all blacklist information'''
        if not ((type(last_query_id) == str) and (last_query_id.isdigit())):
            raise ValueError(
                "get_blacklists parameter 'last_query_id' must be a STRING with a value that's greater than '0'")
        url = "https://{analyzer_ip}/web_service/sample_upload/{service}".format(analyzer_ip=self.analyzer_ip,
                                                                                 service="get_black_lists")
        headers = {
            "X-DTAS-ProtocolVersion": self.protocol_version,
            "X-DTAS-ClientUUID": self.uuid,
            "X-DTAS-Time": self.get_epoch_time(),
            "X-DTAS-Challenge": self.get_challenge(),
            "X-DTAS-ChecksumCalculatingOrder": "X-DTAS-ProtocolVersion,X-DTAS-ClientUUID,X-DTAS-LastQueryID,"
                                               "X-DTAS-Time,X-DTAS-Challenge"
        }
        # Add the X-DTAS-LastQueryID header (default is "0")
        headers["X-DTAS-LastQueryID"] = str(last_query_id)
        # Calculate the header checksum and add it to the list of headers
        headers["X-DTAS-Checksum"] = self.calculate_checksum(headers)
        r = requests.get(url, verify=False, headers=headers)
        return r

    def _register(self):
        '''Send a registration request to register or update registration information on Analyzer.'''
        url = "https://{analyzer_ip}/web_service/sample_upload/{service}".format(analyzer_ip=self.analyzer_ip,
                                                                                 service="register")
        headers = {
            "X-DTAS-ProtocolVersion": self.protocol_version,
            "X-DTAS-ProductName": self.product_name,
            "X-DTAS-ClientHostname": self.client_hostname,
            "X-DTAS-ClientUUID": self.uuid,
            "X-DTAS-SourceID": self.source_id,
            "X-DTAS-SourceName": self.source_name,
            "X-DTAS-Time": self.get_epoch_time(),
            "X-DTAS-Challenge": self.get_challenge(),
            "X-DTAS-ChecksumCalculatingOrder": "X-DTAS-ProtocolVersion,X-DTAS-ProductName,X-DTAS-ClientHostname,"
                                               "X-DTAS-ClientUUID,X-DTAS-SourceID,X-DTAS-SourceName,X-DTAS-Time,"
                                               "X-DTAS-Challenge",
            "X-DTAS-Checksum": ""
        }
        #Calculate the header checksum and add it to the list of headers
        headers["X-DTAS-Checksum"] = self.calculate_checksum(headers)
        r = requests.get(url, verify=False, headers=headers)
        return r

    def _get_system_hostname(self):
        '''Get the hostname of the system from which the script is being run'''
        hostname = platform.node()
        return hostname
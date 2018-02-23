import uuid, time, requests, hashlib, platform, os

from typing import List, Dict

from ..utils.utils import get_challenge, get_epoch_time, get_system_hostname, hash_file

class DDAN:

    def __init__(self, api_key: str, analyzer_ip, protocol_version:str = "1.5", verify_cert:bool = False, cert_path:str = False):
        """
        DDAN used to create an interface for all rest calls offered by DDAN appliance and DTAS.

        :param api_key: ddan api key found under help menu
        :param analyzer_ip: IP of DDAN APPLIANCE
        :param protocol_veriosn: current version is 1.5
        :param verify_cert: path to cert file
        :param cert_path: optional CA certificates to trust for certificate verification
        """
        self.uuid = str(uuid.uuid4())
        self.api_key = api_key
        self.analyzer_ip = analyzer_ip
        self.protocol_version = protocol_version
        self.use_checksum_calculating_order = True
        self.product_name = "TDA"
        self.client_hostname = get_system_hostname()
        self.source_id = "1"  # source_id of 1 == User submission
        self.source_name = "Python ddpy API Client"
        self.verify_cert = verify_cert

        if not verify_cert:
                requests.packages.urllib3.disable_warnings()
        else:
            self.verify_cert = cert_path

        self._register()

    def test_connection(self):
        """
        Issue a request to make sure that all settings are correct and the connection to Analyzer's API is good.

        :return: http response code

        """

        url = "https://{analyzer_ip}/web_service/sample_upload/{service}".format(analyzer_ip=self.analyzer_ip,
                                                                                 service="test_connection")
        headers = {
            "X-DTAS-ProtocolVersion": self.protocol_version,
            "X-DTAS-Time": get_epoch_time(),
            "X-DTAS-Challenge": get_challenge(),
            "X-DTAS-ChecksumCalculatingOrder": "X-DTAS-ProtocolVersion,X-DTAS-Time,X-DTAS-Challenge"
        }
        # Calculate the header checksum and add it to the list of headers
        headers["X-DTAS-Checksum"] = self._calculate_checksum(headers)
        r = requests.get(url, verify=False, headers=headers)
        return r



    def _calculate_checksum(self, headers):
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
            "X-DTAS-Time": get_epoch_time(),
            "X-DTAS-Challenge": get_challenge(),
            "X-DTAS-ChecksumCalculatingOrder": "X-DTAS-ProtocolVersion,X-DTAS-ClientUUID,X-DTAS-LastQueryID,"
                                               "X-DTAS-Time,X-DTAS-Challenge"
        }
        # Add the X-DTAS-LastQueryID header (default is "0")
        headers["X-DTAS-LastQueryID"] = str(last_query_id)
        # Calculate the header checksum and add it to the list of headers
        headers["X-DTAS-Checksum"] = self._calculate_checksum(headers)
        r = requests.get(url, verify=self.verify_cert, headers=headers)
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
            "X-DTAS-Time": get_epoch_time(),
            "X-DTAS-Challenge": get_challenge(),
            "X-DTAS-ChecksumCalculatingOrder": "X-DTAS-ProtocolVersion,X-DTAS-ProductName,X-DTAS-ClientHostname,"
                                               "X-DTAS-ClientUUID,X-DTAS-SourceID,X-DTAS-SourceName,X-DTAS-Time,"
                                               "X-DTAS-Challenge",
            "X-DTAS-Checksum": ""
        }
        #Calculate the header checksum and add it to the list of headers
        headers["X-DTAS-Checksum"] = self._calculate_checksum(headers)
        r = requests.get(url, verify=self.verify_cert, headers=headers)
        return r



    def submit_file(self, path_to_file):
        """
        Upload a file to Analyzer for analysis
        :param path_to_file:

        :return: http response codde
        """

        if not ((type(path_to_file) == str) and (os.path.isfile(path_to_file))):
            raise ValueError(
                "submit_file parameter 'path_to_file' must be a STRING whose value is the path to the file you want to submit")
        url = "https://{analyzer_ip}/web_service/sample_upload/{service}".format(analyzer_ip=self.analyzer_ip,
                                                                                 service="simple_upload_sample")
        sha1 = hash_file(path_to_file)
        headers = {
            "X-DTAS-ProtocolVersion": self.protocol_version,
            "X-DTAS-ClientUUID": self.uuid,
            "X-DTAS-SourceID": self.source_id,
            "X-DTAS-SourceName": self.source_name,
            "X-DTAS-SHA1": sha1,
            "X-DTAS-Time": get_epoch_time(),
            "X-DTAS-SampleType": "0",  # 0 for file, 1 for URL
            "X-DTAS-Challenge": get_challenge(),
            "X-DTAS-ChecksumCalculatingOrder": "X-DTAS-ProtocolVersion,X-DTAS-ClientUUID,X-DTAS-SourceID,X-DTAS-SourceName,X-DTAS-SHA1,X-DTAS-Time,X-DTAS-SampleType,X-DTAS-Challenge",
            "X-DTAS-Checksum": ""
        }
        # Calculate the header checksum and add it to the list of headers
        headers["X-DTAS-Checksum"] = self._calculate_checksum(headers)
        files = {'uploadsample': open(path_to_file, 'rb')}
        r = requests.post(url, verify=self.verify_cert, headers=headers, files=files)
        return r


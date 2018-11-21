from ipmi_helper import IPMIHelper
from Crypto.Cipher import AES
import math

class IPMI15NoAuth():

    def __init__(self, **keys):
        if len(keys) == 1:
            self.ipmi_auth_type = IPMI15NoAuth.extract_ipmi_auth_type(keys['data'])
            self.ipmi_payload_encrypted = None
            self.ipmi_payload_authentication = None
            self.ipmi_payload_type = "IPMI v1.5 payload"
            self.ipmi_session_seq = IPMI15NoAuth.extract_ipmi_session_seq(keys['data'])
            self.ipmi_session_id = IPMI15NoAuth.extract_ipmi_session_id(keys['data'])
            self.message_length = IPMI15NoAuth.extract_message_length(keys['data'])
            self.message_content = IPMI15NoAuth.extract_message_content(keys['data'])
            self.trailer = None
        elif len(keys) == 5:
            self.ipmi_auth_type = keys['ipmi_auth_type']
            self.ipmi_payload_encrypted = None
            self.ipmi_payload_authentication = None
            self.ipmi_payload_type = "IPMI v1.5 payload"
            self.ipmi_session_seq = keys['ipmi_session_seq']
            self.ipmi_session_id = keys['ipmi_session_id']
            self.message_length = keys['message_length']
            self.message_content = keys['message_content']
            self.trailer = None

    @staticmethod
    def extract_ipmi_auth_type(data):
        auth_type = data[0:2]
        return IPMIHelper.get_auth_type(auth_type_byte = auth_type)

    @staticmethod
    def extract_ipmi_session_seq(data):
        session_sequence_number = data[2:10]
        return session_sequence_number

    @staticmethod
    def extract_ipmi_session_id(data):
        session_id = data[10:18]
        return session_id

    @staticmethod
    def extract_message_length(data):
        message_length = data[18:20]
        return int(message_length, 16)

    @staticmethod
    def extract_message_content(data):
        return data[20:]
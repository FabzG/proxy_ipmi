from ipmi_helper import IPMIHelper
from Crypto.Cipher import AES
import math

class IPMI20TrailWrapper():

    def __init__(self, **keys):

        if len(keys) == 1:
            self.ipmi_wrapper_type = "IPMI v2.0 Trail"
            self.ipmi_auth_type = IPMI20TrailWrapper.extract_ipmi_auth_type(keys['data'])
            self.ipmi_payload_encrypted = IPMI20TrailWrapper.extract_ipmi_payload_encryption(keys['data'])
            self.ipmi_payload_authentication = IPMI20TrailWrapper.extract_ipmi_payload_authentication(keys['data'])
            self.ipmi_payload_type = IPMI20TrailWrapper.extract_ipmi_payload_type(keys['data'])
            self.ipmi_session_seq = IPMI20TrailWrapper.extract_ipmi_session_seq(keys['data'])
            self.ipmi_session_id = IPMI20TrailWrapper.extract_ipmi_session_id(keys['data'])
            self.message_length = IPMI20TrailWrapper.extract_message_length(keys['data'])
            self.message_content = IPMI20TrailWrapper.extract_message_content(self.message_length, keys['data'])
            self.trailer = IPMI20TrailWrapper.extract_trailer(self.message_length, keys['data'])
        elif len(keys) == 9:
            self.ipmi_wrapper_type = "IPMI v2.0 Trail"
            self.ipmi_auth_type = keys['ipmi_auth_type']
            self.ipmi_payload_encrypted = keys['ipmi_payload_encrypted']
            self.ipmi_payload_authentication = keys['ipmi_payload_authentication']
            self.ipmi_payload_type = keys['ipmi_payload_type']
            self.ipmi_session_seq = keys['ipmi_session_seq']
            self.ipmi_session_id = keys['ipmi_session_id']
            self.message_length = keys['message_length']
            self.message_content = keys['message_content']
            self.trailer = keys['trailer']

    @staticmethod
    def extract_ipmi_auth_type(data):
        auth_type = data[0:2]
        return IPMIHelper.get_auth_type(auth_type_byte = auth_type)

    @staticmethod
    def extract_ipmi_payload_encryption(data):
        payload_type_byte = data[2:4]
        return IPMIHelper.get_payload_encryption(payload_type_byte)

    @staticmethod
    def extract_ipmi_payload_authentication(data):
        payload_type_byte = data[2:4]
        return IPMIHelper.get_payload_authentication(payload_type_byte)

    @staticmethod
    def extract_ipmi_payload_type(data):
        payload_type_byte = data[2:4]
        return IPMIHelper.get_payload_type(payload_type_byte) 

    @staticmethod
    def extract_ipmi_session_id(data):
        session_id = data[4:12]
        return IPMIHelper.invert_hex(session_id)

    @staticmethod
    def extract_ipmi_session_seq(data):
        session_sequence_number = data[12:20]
        return IPMIHelper.invert_hex(session_sequence_number)


    @staticmethod
    def extract_message_length(data):
        message_length = data[20:24]
        message_length = IPMIHelper.invert_hex(message_length)
        return int(message_length, 16)

    @staticmethod
    def extract_message_content(message_length, data):
        return data[24:24 + (message_length * 2)]

    @staticmethod
    def extract_trailer(message_length, data):
        return data[24 + (message_length * 2):]
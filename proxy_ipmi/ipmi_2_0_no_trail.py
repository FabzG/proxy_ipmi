from ipmi_helper import IPMIHelper
from Crypto.Cipher import AES
import math

class IPMI20NoTrailWrapper():

    def __init__(self, **keys):
        if len(keys) == 1:
            self.ipmi_wrapper_type = "IPMI v2.0 NoTrail"
            self.ipmi_auth_type = IPMI20NoTrailWrapper.extract_ipmi_auth_type(keys['data'])
            self.ipmi_payload_type = IPMI20NoTrailWrapper.extract_ipmi_payload_type(keys['data'])
            self.ipmi_session_seq = IPMI20NoTrailWrapper.extract_ipmi_session_seq(keys['data'])
            self.ipmi_session_id = IPMI20NoTrailWrapper.extract_ipmi_session_id(keys['data'])
            self.message_length = IPMI20NoTrailWrapper.extract_message_length(keys['data'])
            self.message_content = IPMI20NoTrailWrapper.extract_message_content(keys['data'])
            self.trailer = None
        elif len(keys) == 5:
            self.ipmi_wrapper_type = "IPMI v2.0 NoTrail"
            self.ipmi_auth_type = keys['ipmi_auth_type']
            self.ipmi_payload_type = keys['ipmi_payload_type']
            self.ipmi_session_seq = keys['ipmi_session_seq']
            self.ipmi_session_id = keys['ipmi_session_id']
            self.message_length = IPMIHelper.get_message_length(keys['message_content'])
            self.message_content = keys['message_content']
            self.trailer = None
        else:
            raise ValueError("No constructor with " + str(len(keys)) + " arguments.") 

    def __repr__(self):
        return "------- IPMI20NoTrailWrapper -------" \
                + "\nipmi_wrapper_type : " + self.ipmi_wrapper_type \
                + "\nipmi_auth_type : " + self.ipmi_auth_type + " human readable : " + IPMIHelper.get_auth_type(self.ipmi_auth_type) \
                + "\nipmi_payload_type : " + self.ipmi_payload_type \
                + "\n  ipmi_payload_encrypted : " + IPMI20NoTrailWrapper.extract_ipmi_payload_encryption(self.ipmi_payload_type) + " human readable : " + IPMIHelper.get_payload_encryption(self.ipmi_payload_type) \
                + "\n  ipmi_payload_authentication : " + IPMI20NoTrailWrapper.extract_ipmi_payload_authentication(self.ipmi_payload_type) + " human readable : " + IPMIHelper.get_payload_authentication(self.ipmi_payload_type) \
                + "\n  ipmi_payload_type_name : " + IPMIHelper.get_payload_type(self.ipmi_payload_type) \
                + "\nipmi_session_seq : " + self.ipmi_session_seq \
                + "\nipmi_session_id : " + self.ipmi_session_id \
                + "\nmessage_length : " + self.message_length + " human readable : " + str(int(self.message_length, 16)) \
                + "\nmessage_content : " + self.message_content \
                + "\ntrailer : " + str(self.trailer)

    def serialize(self):
        return self.ipmi_auth_type + self.ipmi_payload_type + self.ipmi_session_seq + self.ipmi_session_id + self.message_length + self.message_content

    @staticmethod
    def extract_ipmi_auth_type(data):
        auth_type = data[0:2]
        return auth_type

    @staticmethod
    def extract_ipmi_payload_encryption(data):
        payload_type_bits = IPMIHelper.get_bits(data)
        encryption_status = payload_type_bits[7]

        return encryption_status

    @staticmethod
    def extract_ipmi_payload_authentication(data):
        payload_type_bits = IPMIHelper.get_bits(data)
        authentication_status = payload_type_bits[6]
        
        return authentication_status

    @staticmethod
    def extract_ipmi_payload_type(data):
        payload_type_byte = data[2:4]
        return payload_type_byte

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
        return IPMIHelper.invert_hex(message_length)

    @staticmethod
    def extract_message_content(data):
        return data[24:]
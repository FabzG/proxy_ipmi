from ipmi_helper import IPMIHelper
from Crypto.Cipher import AES
import hmac
import math
from hashlib import sha1

class IPMI20TrailWrapper():

    def __init__(self, **keys):

        if len(keys) == 1:
            self.ipmi_wrapper_type = "IPMI v2.0 Trail"
            self.ipmi_auth_type = IPMI20TrailWrapper.extract_ipmi_auth_type(keys['data'])
            #self.ipmi_payload_encrypted = IPMI20TrailWrapper.extract_ipmi_payload_encryption(keys['data'])
            #self.ipmi_payload_authentication = IPMI20TrailWrapper.extract_ipmi_payload_authentication(keys['data'])
            self.ipmi_payload_type = IPMI20TrailWrapper.extract_ipmi_payload_type(keys['data'])
            self.ipmi_session_seq = IPMI20TrailWrapper.extract_ipmi_session_seq(keys['data'])
            self.ipmi_session_id = IPMI20TrailWrapper.extract_ipmi_session_id(keys['data'])
            self.message_length = IPMI20TrailWrapper.extract_message_length(keys['data'])
            self.message_content = IPMI20TrailWrapper.extract_message_content(self.message_length, keys['data'])
            self.trailer = IPMI20TrailWrapper.extract_trailer(self.message_length, keys['data'])
            self.sik = None
            self.RCMP_auth_algorithm = None
        elif len(keys) == 7:
            self.ipmi_wrapper_type = "IPMI v2.0 Trail"
            self.ipmi_auth_type = keys['ipmi_auth_type']
            self.ipmi_payload_type = keys['ipmi_payload_type']
            self.ipmi_session_seq = keys['ipmi_session_seq']
            self.ipmi_session_id = keys['ipmi_session_id']
            self.message_content = keys['message_content']
            self.sik = keys['sik']
            self.RCMP_auth_algorithm = keys['RCMP_auth_algorithm']
            self.message_length = IPMIHelper.calculate_message_length_2_bytes(self.message_content)
            self.trailer = IPMI20TrailWrapper.calculate_trailer(self)

        else:
            raise ValueError("No constructor with " + str(len(keys)) + " arguments.") 

    def __repr__(self):
        return "------- IPMI20TrailWrapper -------" \
                + "\nipmi_wrapper_type : " + self.ipmi_wrapper_type \
                + "\nipmi_auth_type : " + self.ipmi_auth_type + " human readable : " + IPMIHelper.get_auth_type(self.ipmi_auth_type) \
                + "\nipmi_payload_type : " + self.ipmi_payload_type \
                + "\n  ipmi_payload_encrypted : " + IPMI20TrailWrapper.extract_ipmi_payload_encryption(self.ipmi_payload_type) + " human readable : " + IPMIHelper.get_payload_encryption(self.ipmi_payload_type) \
                + "\n  ipmi_payload_authentication : " + IPMI20TrailWrapper.extract_ipmi_payload_authentication(self.ipmi_payload_type) + " human readable : " + IPMIHelper.get_payload_authentication(self.ipmi_payload_type) \
                + "\n  ipmi_payload_type_name : " + IPMIHelper.get_payload_type(self.ipmi_payload_type) \
                + "\nipmi_session_seq : " + self.ipmi_session_seq \
                + "\nipmi_session_id : " + self.ipmi_session_id \
                + "\nmessage_length : " + self.message_length + " human readable : " + str(int(self.message_length, 16)) \
                + "\nmessage_content : " + self.message_content \
                + "\ntrailer : " + str(self.trailer)


    def serialize(self):
        return self.ipmi_auth_type + self.ipmi_payload_type + IPMIHelper.invert_hex(self.ipmi_session_id) + self.ipmi_session_seq +  self.message_length + self.message_content + self.trailer

    def calculate_trailer(self):

        message_content = self.ipmi_auth_type + self.ipmi_payload_type + IPMIHelper.invert_hex(self.ipmi_session_id) + self.ipmi_session_seq +  self.message_length + self.message_content
        message_length = len(message_content)

        bytes_to_pad = int(((message_length / 2) % 8) - 2)

        trailer = 'ff' * bytes_to_pad

        pad_size = hex(bytes_to_pad)[2:]

        if len(pad_size) < 2:
            pad_size = '0' + pad_size
       
        trailer = trailer + pad_size + '07'

        k1_key = self.generate_ipmi_k1_key()
        auth_code = self.generate_trailer_auth(message_content + trailer)

        return trailer + auth_code


    @staticmethod
    def extract_ipmi_auth_type(data):
        auth_type = data[0:2]
        #return IPMIHelper.get_auth_type(auth_type_byte = auth_type)
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
        #return IPMIHelper.get_payload_type(payload_type_byte) 
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
        message_length = IPMIHelper.invert_hex(message_length)
        #return int(message_length, 16)
        return message_length

    @staticmethod
    def extract_message_content(message_length, data):
        return data[24:24 + (int(message_length, 16) * 2)]

    @staticmethod
    def extract_trailer(message_length, data):
        return data[24 + (int(message_length, 16)* 2):]

    def generate_ipmi_k1_key(self):
        if self.RCMP_auth_algorithm == 'RAKP-HMAC-SHA1':

            complement = '01'*20
            hmac_sik = hmac.new(bytes.fromhex(self.sik)
            , bytes.fromhex(complement)
            , sha1)
        else:
            raise AttributeError('Authentication algorithm ' + self.RCMP_auth_algorithm + ' not implemented')

        return hmac_sik.digest().hex()

    def generate_trailer_auth(self, message):
        if self.RCMP_auth_algorithm == 'RAKP-HMAC-SHA1':
            #test = self.RAKP_message_1_remote_console_random_number + self.managed_system_random_number + self.RAKP_message_1_requested_max_privilege + self.RAKP_message_1_user_name_length + self.RAKP_message_1_user_name
            hmac_sik = hmac.new(bytes.fromhex(self.generate_ipmi_k1_key())
            , bytes.fromhex(message)
            , sha1)
        else:
            raise AttributeError('Authentication algorithm ' + self.RCMP_auth_algorithm + ' not implemented')

        return hmac_sik.digest().hex()[0:24]

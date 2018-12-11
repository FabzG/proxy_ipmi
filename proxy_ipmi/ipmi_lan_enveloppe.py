from Crypto.Cipher import AES
from ipmi_helper import IPMIHelper
from payload_ipmi_lan_resp_msg import IPMILanResponse
from ipmi_lan_factory import IPMILanFactory
import math
from hashlib import sha1
import hmac
import math

class IPMILanEnveloppe():

    def __init__(self, **keys):#ciphered_msg, ipmi_sik, RCMP_auth_algorithm):

        if len(keys) == 2 and keys['wrapper_type'] == "IPMI v1.5":
            self.message_type = IPMIHelper.guess_ipmi_message_type(data = keys['data'])
            self.ciphered_msg = None
            self.ipmi_sik = None
            self.RCMP_auth_algorithm = None
            self.ipmi_k2_key = None
            self.ipmi_k2_short_key = None
            self.iv = None
            self.uncipherded_payload = keys['data']
            self.ipmi_lan_message = IPMILanFactory.get_ipmi_message_instance(message_type = self.message_type, data = keys['data'])
        elif len(keys) == 4 and keys['wrapper_type'] == "IPMI v2.0 Trail":
            self.ciphered_msg = keys['ciphered_msg']
            self.ipmi_sik = keys['ipmi_sik']
            self.RCMP_auth_algorithm = keys['RCMP_auth_algorithm']
            self.ipmi_k2_key = self.generate_ipmi_k2_key()
            self.ipmi_k2_short_key = self.extract_ipmi_k2_short_key()
            self.iv = self.extract_iv()
            self.uncipherded_payload = self.decrypt_msg()
            self.message_type = IPMIHelper.guess_ipmi_message_type(data = self.uncipherded_payload)
            self.ipmi_lan_message = IPMILanFactory.get_ipmi_message_instance(message_type = self.message_type, data = self.uncipherded_payload)
        elif len(keys) in (8, 9):
            self.ciphered_msg = None
            self.ipmi_sik = None
            self.RCMP_auth_algorithm = None
            self.ipmi_k2_key = None
            self.ipmi_k2_short_key = None
            self.iv = None
            self.message_type = "Request" if len(keys) == 8 else "Response"
            self.ipmi_lan_message = IPMILanFactory.get_ipmi_message_instance(message_type = self.message_type, data = self.filter_dictionnary(keys))
            self.uncipherded_payload = self.ipmi_lan_message.serialize()
        elif len(keys) in (10, 11):
            self.ipmi_sik = keys['ipmi_sik']
            self.RCMP_auth_algorithm = keys['RCMP_auth_algorithm']
            self.ipmi_k2_key = self.generate_ipmi_k2_key()
            self.ipmi_k2_short_key = self.extract_ipmi_k2_short_key()
            self.iv = IPMIHelper.generate_ipmi_iv()
            self.message_type = "Request" if len(keys) == 10 else "Response"
            self.ipmi_lan_message = IPMILanFactory.get_ipmi_message_instance(message_type = self.message_type, data = self.filter_dictionnary(keys))
            self.uncipherded_payload = self.ipmi_lan_message.serialize()
            self.ciphered_msg = self.generate_ciphered_message()
            
        else:
            raise ValueError("No constructor with " + str(len(keys)) + " arguments.") 

    def __repr__(self):
        
        return "------- IPMILanMessage -------" \
                + "\nmessage_type : " + self.message_type \
                + "\nciphered_msg : " + str(self.ciphered_msg) \
                + "\nipmi_sik : " + str(self.ipmi_sik) \
                + "\nRCMP_auth_algorithm : " + str(self.RCMP_auth_algorithm) \
                + "\nipmi_k2_key : " + str(self.ipmi_k2_key) \
                + "\nipmi_k2_short_key : " + str(self.ipmi_k2_short_key) \
                + "\niv : " + str(self.iv) \
                + "\nuncipherded_payload : " + str(self.uncipherded_payload) \
                + str(self.ipmi_lan_message)

    def serialize(self):
        if self.ciphered_msg:
            return self.ciphered_msg
        else:
            return self.uncipherded_payload
    '''
    def hex_netFN_rsLUN(net_fn, rs_lun):
        return IPMIHelper.hexify_binary_string(net_fn, rs_lun)

    def hex_rqSeq_rqLUN(rq_seq, rq_lun):
        return IPMIHelper.hexify_binary_string(rq_seq, rq_lun)

    def hex_netFN_rqLUN(net_fn, rq_lun):
        return IPMIHelper.hexify_binary_string(net_fn, rq_lun)

    def hex_rqSeq_rsLUN(rq_seq, rs_lun):
        return IPMIHelper.hexify_binary_string(rq_seq, rs_lun)
    '''
    def filter_dictionnary(self, dict_data):
        try:
            
            if 'request_data' in dict_data:
                filtered_dict = {}
                filtered_dict['rsAddr'] = dict_data['rsAddr']
                filtered_dict['netFn'] = dict_data['netFn']
                filtered_dict['rsLUN'] = dict_data['rsLUN']
                filtered_dict['rqAddr'] = dict_data['rqAddr']
                filtered_dict['rqSeq'] = dict_data['rqSeq']
                filtered_dict['rqLUN'] = dict_data['rqLUN']
                filtered_dict['command'] = dict_data['command']
                filtered_dict['request_data'] = dict_data['request_data']
                return filtered_dict
            elif 'response_data' in dict_data:
                filtered_dict = {}
                filtered_dict['rqAddr'] = dict_data['rqAddr']
                filtered_dict['netFn'] = dict_data['netFn']
                filtered_dict['rqLUN'] = dict_data['rqLUN']
                filtered_dict['rsAddr'] = dict_data['rsAddr']
                filtered_dict['rqSeq'] = dict_data['rqSeq']
                filtered_dict['rsLUN'] = dict_data['rsLUN']
                filtered_dict['command'] = dict_data['command']
                filtered_dict['completion_code'] = dict_data['completion_code']
                filtered_dict['response_data'] = dict_data['response_data']
                return filtered_dict
            else:
                raise AttributeError("Attribute is not a correct dictionnary of parametrized IPMI message.")
        except:
            raise AttributeError("Attribute is not a correct dictionnary of parametrized IPMI message.")

    '''
    def generate_unciphered_message(self):
        unciphered_message = self.ipmi_lan_response_message.rqAddr + self.ipmi_lan_response_message.hex_netFN_rqLUN() + self.ipmi_lan_response_message.checksum1 + self.ipmi_lan_response_message.rsAddr + self.ipmi_lan_response_message.hex_rqSeq_rsLUN() + self.ipmi_lan_response_message.command + self.ipmi_lan_response_message.completion_code + self.ipmi_lan_response_message.response_data + self.ipmi_lan_response_message.checksum2
    
        return unciphered_message
    '''
    def generate_ciphered_message(self):

        padded_message = IPMIHelper.pad_aes_ipmi_lan_decrypted_msg(self.uncipherded_payload)
        
        aes = AES.new(bytes.fromhex(self.ipmi_k2_short_key), AES.MODE_CBC, bytes.fromhex(self.iv))
        encrypted_msg = aes.encrypt(bytes.fromhex(padded_message))

        return self.iv + encrypted_msg.hex()
    '''
    def generate_checksum_one(self):
        bytes_to_check = self.ipmi_lan_message.rqAddr + self.ipmi_lan_message.hex_netFN_rqLUN
        calculated_checksum = IPMIHelper.two_complement_checksum(bytes_to_check)

        return calculated_checksum

    def generate_checksum_two(self):
        bytes_to_check = self.ipmi_lan_message.rsAddr + self.ipmi_lan_message.hex_rqSeq_rsLUN() + self.ipmi_lan_message.command + self.ipmi_lan_message.completion_code + self.ipmi_lan_message.response_data
        calculated_checksum = IPMIHelper.two_complement_checksum(bytes_to_check)

        return calculated_checksum
    '''
    def decrypt_msg(self):
        print("ipmi_ciphered_payload : " + str(self.ciphered_msg[32:]))
        aes = AES.new(bytes.fromhex(self.ipmi_k2_short_key), AES.MODE_CBC, bytes.fromhex(self.iv))
        decrypted_msg = aes.decrypt(bytes.fromhex(self.ciphered_msg[32:]))
        return IPMIHelper.unpad_ipmi_lan_decrypted_msg(decrypted_msg.hex())

    def generate_ipmi_k1_key(self):
        if self.RCMP_auth_algorithm == 'RAKP-HMAC-SHA1':
            #test = self.RAKP_message_1_remote_console_random_number + self.managed_system_random_number + self.RAKP_message_1_requested_max_privilege + self.RAKP_message_1_user_name_length + self.RAKP_message_1_user_name
            complement = '01'*20
            hmac_sik = hmac.new(bytes.fromhex(self.ipmi_sik)
            , bytes.fromhex(complement)
            , sha1)
        else:
            raise AttributeError('Authentication algorithm ' + self.RCMP_auth_algorithm + ' not implemented')

        return hmac_sik.digest().hex()

    def generate_ipmi_k2_key(self):
        if self.RCMP_auth_algorithm == 'RAKP-HMAC-SHA1':
            #test = self.RAKP_message_1_remote_console_random_number + self.managed_system_random_number + self.RAKP_message_1_requested_max_privilege + self.RAKP_message_1_user_name_length + self.RAKP_message_1_user_name
            complement = '02'*20
            hmac_sik = hmac.new(bytes.fromhex(self.ipmi_sik)
            , bytes.fromhex(complement)
            , sha1)
        else:
            raise AttributeError('Authentication algorithm ' + self.RCMP_auth_algorithm + ' not implemented')

        return hmac_sik.digest().hex()

    def extract_ipmi_k2_short_key(self):
        k2_short_key = self.ipmi_k2_key[0:32]
        print("ipmi_k2_short_key : " + str(k2_short_key))
        return k2_short_key
    '''
    def extract_rqAddr(self):
        return self.uncipherded_payload[0:2]

    def extract_rsAddr(self):
        return self.uncipherded_payload[6:8]

    def extract_netFn(self):
        netFn_rqlun = self.uncipherded_payload[2:4]
        bits_netFn_rqlun = IPMIHelper.get_bits(netFn_rqlun)

        return "".join(bits_netFn_rqlun[2:])

    def extract_rqLUN(self):
        netFn_rqLUN = self.uncipherded_payload[2:4]
        bits_netFn_rqLUN = IPMIHelper.get_bits(netFn_rqLUN)

        return "".join(bits_netFn_rqLUN[0:2])

    def extract_rqSeq(self):
        rqSeq_rsLUN = self.uncipherded_payload[8:10]
        bits_rqSeq_rsLUN = IPMIHelper.get_bits(rqSeq_rsLUN)

        return "".join(bits_rqSeq_rsLUN[2:])

    def extract_rsLUN(self):
        rqSeq_rsLUN = self.uncipherded_payload[8:10]
        bits_rqSeq_rsLUN = IPMIHelper.get_bits(rqSeq_rsLUN)

        return "".join(bits_rqSeq_rsLUN[0:2])
    '''
    def extract_iv(self):
        print("ipmi_iv : " + str(self.ciphered_msg[0:32]))
        return self.ciphered_msg[0:32]

    def extract_checksum_one(self):
        return self.uncipherded_payload[4:6]
    '''
    def validate_checksum_one(self):
        bytes_to_check = self.ipmi_lan_message.rqAddr + self.ipmi_lan_response_message.hex_netFN_rqLUN()
        calculated_checksum = IPMIHelper.two_complement_checksum(bytes_to_check)
        if calculated_checksum != self.ipmi_lan_response_message.checksum2:
            raise AssertionError()
            #print("WRONG CHECKSUM !! calc : " + calculated_checksum)
    
    def extract_command(self):
        return self.uncipherded_payload[10:12]

    def extract_completion_code(self):
        return self.uncipherded_payload[12:14]

    def extract_response_data(self):
        return self.uncipherded_payload[14:-2]
           
    def extract_checksum_two(self):
        return self.uncipherded_payload[-2:]

    def validate_checksum_two(self):
        bytes_to_check = self.ipmi_lan_response_message.rsAddr + self.ipmi_lan_response_message.hex_rqSeq_rsLUN + self.ipmi_lan_response_message.command + self.ipmi_lan_response_message.completion_code + self.ipmi_lan_response_message.response_data
        calculated_checksum = IPMIHelper.two_complement_checksum(bytes_to_check)
        if calculated_checksum != self.ipmi_lan_response_message.checksum2:
            raise AssertionError()
            #print("WRONG CHECKSUM !! calc : " + calculated_checksum)
    '''

    
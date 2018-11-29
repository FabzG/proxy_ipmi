from Crypto.Cipher import AES
from ipmi_helper import IPMIHelper
from payload_ipmi_lan_resp_msg import IPMILanResponse
import math
from hashlib import sha1
import hmac
import math

class IPMICipheredLanResponse():

    def __init__(self, **keys):#ciphered_msg, ipmi_sik, RCMP_auth_algorithm):

        if len(keys) == 3:
            self.ciphered_msg = keys['ciphered_msg']
            self.ipmi_sik = keys['ipmi_sik']
            self.RCMP_auth_algorithm = keys['RCMP_auth_algorithm']
            self.ipmi_k2_key = self.generate_ipmi_k2_key()
            self.ipmi_k2_short_key = self.extract_ipmi_k2_short_key()
            self.iv = self.extract_iv()
            self.uncipherded_payload = self.decrypt_msg()
            self.ipmi_lan_response_message = IPMILanResponse(rqAddr=self.extract_rqAddr(),
                                                            netFn= self.extract_netFn(),
                                                            rqLUN=self.extract_rqLUN(),
                                                            rsAddr=self.extract_rsAddr(),
                                                            rqSeq=self.extract_rqSeq(),
                                                            rsLUN=self.extract_rsLUN(),
                                                            command=self.extract_command(),
                                                            completion_code=self.extract_completion_code(),
                                                            response_data=self.extract_response_data())
        elif len(keys) == 11:
            self.ipmi_sik = keys['ipmi_sik']
            self.RCMP_auth_algorithm = keys['RCMP_auth_algorithm']
            self.ipmi_k2_key = self.generate_ipmi_k2_key()
            self.ipmi_k2_short_key = self.extract_ipmi_k2_short_key()
            self.iv = IPMIHelper.generate_ipmi_iv()
            self.ipmi_lan_response_message = IPMILanResponse(rqAddr=keys['rqAddr'],
                                                            netFn=keys['netFn'],
                                                            rqLUN=keys['rqlun'],
                                                            rsAddr=keys['rsAddr'],
                                                            rqSeq=keys['rqSeq'],
                                                            rsLUN=keys['rsLUN'],
                                                            command=keys['command'],
                                                            completion_code=keys['completion_code'],
                                                            response_data=keys['response_data'])
            self.uncipherded_payload = self.ipmi_lan_response_message.serialize()#self.generate_unciphered_message()
            self.ciphered_msg = self.generate_ciphered_message()
        else:
            raise ValueError("No constructor with " + str(len(keys)) + " arguments.") 

    def __repr__(self):
        return "------- IPMILanResponseMessage -------" \
                + "\nciphered_msg : " + self.ciphered_msg \
                + "\nipmi_sik : " + self.ipmi_sik \
                + "\nRCMP_auth_algorithm : " + self.RCMP_auth_algorithm \
                + "\nipmi_k2_key : " + self.ipmi_k2_key \
                + "\nipmi_k2_short_key : " + self.ipmi_k2_short_key \
                + "\niv : " + self.iv\
                + "\nuncipherded_payload : " + self.uncipherded_payload\
                + "\nrqAddr : " + self.ipmi_lan_response_message.rqAddr \
                + "\nnetFn_rqlun : " + self.ipmi_lan_response_message.hex_netFN_rqLUN() \
                + "\n  netFn : " + self.ipmi_lan_response_message.netFn + " human readable : " + IPMIHelper.get_netFn_definition(self.ipmi_lan_response_message.netFn) \
                + "\n  rqlun : " + self.ipmi_lan_response_message.rqLUN \
                + "\nchecksum_one : " + self.ipmi_lan_response_message.checksum1 \
                + "\nrsAddr : " + self.ipmi_lan_response_message.rsAddr \
                + "\nrqSeq_rsLun : " + self.ipmi_lan_response_message.hex_rqSeq_rsLUN() \
                + "\n  rqSeq : " + self.ipmi_lan_response_message.rqSeq \
                + "\n  rsLun : " + self.ipmi_lan_response_message.rsLUN \
                + "\ncommand : " + self.ipmi_lan_response_message.command \
                + "\ncompletion_code : " + self.ipmi_lan_response_message.completion_code \
                + "\nresponse_data : " + self.ipmi_lan_response_message.response_data \
                + "\nchecksum_two : " + self.ipmi_lan_response_message.checksum2

    def serialize(self):
        return self.ciphered_msg
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

    def generate_checksum_one(self):
        bytes_to_check = self.ipmi_lan_response_message.rqAddr + self.ipmi_lan_response_message.hex_netFN_rqLUN
        calculated_checksum = IPMIHelper.two_complement_checksum(bytes_to_check)

        return calculated_checksum

    def generate_checksum_two(self):
        bytes_to_check = self.ipmi_lan_response_message.rsAddr + self.ipmi_lan_response_message.hex_rqSeq_rsLUN() + self.ipmi_lan_response_message.command + self.ipmi_lan_response_message.completion_code + self.ipmi_lan_response_message.response_data
        calculated_checksum = IPMIHelper.two_complement_checksum(bytes_to_check)

        return calculated_checksum

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

    def extract_iv(self):
        print("ipmi_iv : " + str(self.ciphered_msg[0:32]))
        return self.ciphered_msg[0:32]

    def extract_checksum_one(self):
        return self.uncipherded_payload[4:6]

    def validate_checksum_one(self):
        bytes_to_check = self.ipmi_lan_response_message.rqAddr + self.ipmi_lan_response_message.hex_netFN_rqLUN()
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

    
from Crypto.Cipher import AES
from payload_ipmi_lan_req_msg import IPMILanRequest
from ipmi_helper import IPMIHelper
from hashlib import sha1
import hmac
import math

class IPMICipheredLanRequest():

    def __init__(self, **keys):#ciphered_msg, ipmi_sik, RCMP_auth_algorithm):
        if len(keys) == 3:
            self.ciphered_msg = keys['ciphered_msg']
            self.ipmi_sik = keys['ipmi_sik']
            self.RCMP_auth_algorithm = keys['RCMP_auth_algorithm']
            self.ipmi_k2_key = self.generate_ipmi_k2_key()
            self.ipmi_k2_short_key = self.extract_ipmi_k2_short_key()
            self.iv = self.extract_iv()
            self.uncipherded_payload = self.decrypt_msg()
            self.ipmi_lan_request_message = IPMILanRequest(rsAddr=self.extract_rsAddr(),
                                                            netFn=self.extract_netFn(),
                                                            rsLUN=self.extract_rsLUN(),
                                                            rqAddr=self.extract_rqAddr(),
                                                            rqSeq=self.extract_rqSeq(),
                                                            rqLUN=self.extract_rqLUN(),
                                                            command=self.extract_command(),
                                                            request_data=self.extract_command_data()
                                                            )
        elif len(keys) == 10:
            self.ipmi_sik = keys['ipmi_sik']
            self.RCMP_auth_algorithm = keys['RCMP_auth_algorithm']
            self.ipmi_k2_key = self.generate_ipmi_k2_key()
            self.ipmi_k2_short_key = self.extract_ipmi_k2_short_key()
            self.iv = IPMIHelper.generate_ipmi_iv()
            self.ipmi_lan_request_message = IPMILanRequest(rsAddr=keys['rsAddr'],
                                                            netFn=keys['netFn'],
                                                            rsLUN=keys['rsLUN'],
                                                            rqAddr=keys['rqAddr'],
                                                            rqSeq=keys['rqSeq'],
                                                            rqLUN=keys['rqLUN'],
                                                            command=keys['command'],
                                                            request_data=keys['request_data']
                                                            )
            self.uncipherded_payload = self.ipmi_lan_request_message.serialize()
            self.ciphered_msg = self.generate_ciphered_message()
        else:
            raise ValueError("No constructor with " + str(len(keys)) + " arguments.") 

    def __repr__(self):
        return "------- IPMILanRequestMessage -------" \
                + "\nciphered_msg : " + self.ciphered_msg \
                + "\nipmi_sik : " + self.ipmi_sik \
                + "\nRCMP_auth_algorithm : " + self.RCMP_auth_algorithm \
                + "\nipmi_k2_key : " + self.ipmi_k2_key \
                + "\nipmi_k2_short_key : " + self.ipmi_k2_short_key \
                + "\niv : " + self.iv\
                + "\nrsAddr : " + self.ipmi_lan_request_message.rsAddr \
                + "\nnetFn_rslun : " + self.ipmi_lan_request_message.hex_netFN_rsLUN() \
                + "\n  netFn : " + self.ipmi_lan_request_message.netFn + " human readable : " + IPMIHelper.get_netFn_definition(self.ipmi_lan_request_message.netFn)\
                + "\n  rslun : " + self.ipmi_lan_request_message.rsLUN \
                + "\nchecksum_one : " + self.ipmi_lan_request_message.checksum1 \
                + "\nrqAddr : " + self.ipmi_lan_request_message.rqAddr \
                + "\nrqSeq_rqLun : " + self.ipmi_lan_request_message.hex_rqSeq_rqLUN() \
                + "\n  rqSeq : " + self.ipmi_lan_request_message.rqSeq \
                + "\n  rqLun : " + self.ipmi_lan_request_message.rqLUN \
                + "\ncommand : " + self.ipmi_lan_request_message.command \
                + "\ncommand_data : " + self.ipmi_lan_request_message.request_data \
                + "\nchecksum_two : " + self.ipmi_lan_request_message.checksum2


    def decrypt_msg(self):
        print("ipmi_ciphered_payload : " + str(self.ciphered_msg[32:]))
        aes = AES.new(bytes.fromhex(self.ipmi_k2_short_key), AES.MODE_CBC, bytes.fromhex(self.iv))
        decrypted_msg = aes.decrypt(bytes.fromhex(self.ciphered_msg[32:]))
        return IPMIHelper.unpad_ipmi_lan_decrypted_msg(decrypted_msg.hex())

    def generate_ciphered_message(self):

        padded_message = IPMIHelper.pad_aes_ipmi_lan_decrypted_msg(self.uncipherded_payload)
        
        aes = AES.new(bytes.fromhex(self.ipmi_k2_short_key), AES.MODE_CBC, bytes.fromhex(self.iv))
        encrypted_msg = aes.encrypt(bytes.fromhex(padded_message))

        return self.iv + encrypted_msg.hex()

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

    def extract_rsAddr(self):
        return self.uncipherded_payload[0:2]

    def extract_rqAddr(self):
        return self.uncipherded_payload[6:8]

    def extract_netFn(self):
        netFn_LUN = self.uncipherded_payload[2:4]
        bits_netFn_LUN = IPMIHelper.get_bits(netFn_LUN)

        return "".join(bits_netFn_LUN[2:])

    def extract_rsLUN(self):
        netFn_LUN = self.uncipherded_payload[2:4]
        bits_netFn_LUN = IPMIHelper.get_bits(netFn_LUN)

        return  "".join(bits_netFn_LUN[0:2])

    def extract_rqSeq(self):
        rqSeq_rqLUN = self.uncipherded_payload[8:10]
        bits_rqSeq_rqLUN = IPMIHelper.get_bits(rqSeq_rqLUN)

        return "".join(bits_rqSeq_rqLUN[2:])

    def extract_rqLUN(self):
        rqSeq_rqLUN = self.uncipherded_payload[8:10]
        bits_rqSeq_rqLUN = IPMIHelper.get_bits(rqSeq_rqLUN)

        return "".join(bits_rqSeq_rqLUN[0:2])

    def extract_iv(self):
        print("ipmi_iv : " + str(self.ciphered_msg[0:32]))
        return self.ciphered_msg[0:32]

    def extract_checksum_rsAdd_netFn_rsLun(self):
        return self.uncipherded_payload[4:6]

    def validate_checksum_rsAdd_netFn_rsLun(self):
        bytes_to_check = self.ipmi_lan_request_message.rsAddr + self.ipmi_lan_request_message.hex_netFN_rsLUN()
        calculated_checksum = IPMIHelper.two_complement_checksum(bytes_to_check)
        if calculated_checksum != self.ipmi_lan_request_message.checksum1:
            raise AssertionError()
            #print("WRONG CHECKSUM !! calc : " + calculated_checksum)

    def extract_command(self):
        return self.uncipherded_payload[10:12]

    def extract_command_data(self):
        return self.uncipherded_payload[12:-2]
           
    def extract_checksum_two(self):
        return self.uncipherded_payload[-2:]

    def validate_checksum_two(self):
        bytes_to_check = self.ipmi_lan_request_message.rqAddr + self.ipmi_lan_request_message.hex_rqSeq_rqLUN() + self.ipmi_lan_request_message.command + self.ipmi_lan_request_message.command_data
        calculated_checksum = IPMIHelper.two_complement_checksum(bytes_to_check)
        if calculated_checksum != self.ipmi_lan_request_message.checksum2:
            raise AssertionError()
            #print("WRONG CHECKSUM !! calc : " + calculated_checksum)
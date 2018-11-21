from Crypto.Cipher import AES
#from ipmi_lan_msg import IPMILanMessage
from ipmi_helper import IPMIHelper
import math
from hashlib import sha1
import hmac
import math

class IPMILanResponseMessage():

    def __init__(self, ciphered_msg, ipmi_sik, RCMP_auth_algorithm):
        self.ciphered_msg = ciphered_msg
        self.ipmi_sik = ipmi_sik
        self.RCMP_auth_algorithm = RCMP_auth_algorithm
        self.ipmi_k2_key = self.generate_ipmi_k2_key()
        self.ipmi_k2_short_key = self.extract_ipmi_k2_short_key()
        self.iv = self.extract_iv()
        self.uncipherded_payload = self.decrypt_msg()
        self.rqAddr = self.extract_rqAddr()
        self.netFn_rqlun  = self.extract_netFn_rqlun()
        self.checksum_one = self.extract_checksum_one()
        self.validate_checksum_one()
        self.rsAddr = self.extract_rsAddr()
        self.rqSeq_rsLun  = self.extract_rqSeq_rslun()
        self.command = self.extract_command()
        self.completion_code = self.extract_completion_code()
        self.response_data = self.extract_response_data()
        self.checksum_two = self.extract_checksum_two()
        self.validate_checksum_two()

    def __repr__(self):
        return "------- IPMILanResponseMessage -------" \
                + "\nciphered_msg : " + self.ciphered_msg \
                + "\nipmi_sik : " + self.ipmi_sik \
                + "\nRCMP_auth_algorithm : " + self.RCMP_auth_algorithm \
                + "\nipmi_k2_key : " + self.ipmi_k2_key \
                + "\nipmi_k2_short_key : " + self.ipmi_k2_short_key \
                + "\niv : " + self.iv\
                + "\nuncipherded_payload : " + self.uncipherded_payload\
                + "\nrqAddr : " + self.rqAddr \
                + "\nnetFn_rqlun : " + self.netFn_rqlun \
                + "\n  netFn : " + self.extract_netFn() + " human readable : " + IPMIHelper.get_netFn_definition(self.extract_netFn())\
                + "\n  rqlun : " + self.extract_rqLun() \
                + "\nchecksum_one : " + self.checksum_one \
                + "\nrsAddr : " + self.rsAddr \
                + "\nrqSeq_rsLun : " + self.rqSeq_rsLun \
                + "\n  rqSeq : " + self.extract_rqSeq() \
                + "\n  rsLun : " + self.extract_rsLun() \
                + "\ncommand : " + self.command \
                + "\ncompletion_code : " + self.completion_code \
                + "\nresponse_data : " + self.response_data \
                + "\nchecksum_two : " + self.checksum_two

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

    def extract_netFn_rqlun(self):
        netFn_lun = self.uncipherded_payload[2:4]
        return netFn_lun

    def extract_rqSeq_rslun(self):
        rqSeq_rqlun = self.uncipherded_payload[8:10]
        return rqSeq_rqlun

    def extract_netFn(self):
        netFn = IPMILanResponseMessage.get_bits(self.netFn_rqlun)[2:]
        netFn.reverse
        return "".join(netFn)

    def extract_rqLun(self):
        lun = IPMILanResponseMessage.get_bits(self.netFn_rqlun)[0:2]
        lun.reverse
        return "".join(lun)

    def extract_rqSeq(self):
        rqSeq = IPMILanResponseMessage.get_bits(self.rqSeq_rsLun)[2:]
        rqSeq.reverse
        return "".join(rqSeq)

    def extract_rsLun(self):
        rqLun = IPMILanResponseMessage.get_bits(self.rqSeq_rsLun)[0:2]
        rqLun.reverse
        return "".join(rqLun)

    def extract_iv(self):
        print("ipmi_iv : " + str(self.ciphered_msg[0:32]))
        return self.ciphered_msg[0:32]

    def extract_checksum_one(self):
        return self.uncipherded_payload[4:6]

    def validate_checksum_one(self):
        bytes_to_check = self.rqAddr + self.netFn_rqlun
        calculated_checksum = IPMILanResponseMessage.two_complement_checksum(bytes_to_check)
        if calculated_checksum != self.checksum_one:
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
        bytes_to_check = self.rsAddr + self.rqSeq_rsLun + self.command + self.completion_code + self.response_data
        calculated_checksum = IPMILanResponseMessage.two_complement_checksum(bytes_to_check)
        if calculated_checksum != self.checksum_two:
            raise AssertionError()
            #print("WRONG CHECKSUM !! calc : " + calculated_checksum)

    
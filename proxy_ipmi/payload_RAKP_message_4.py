from ipmi_helper import IPMIHelper
from hashlib import sha1
import hmac

class PayloadRAKPMessage4():

    def __init__(self, **keys):

        if len(keys) == 1:
            self.RAKP_message_3_message_tag = PayloadRAKPMessage4.extract_message_tag(keys['data'])
            self.rcmp_status_code = PayloadRAKPMessage4.extract_rcmp_status_code(keys['data'])
            self.reserved = PayloadRAKPMessage4.extract_reserved(keys['data'])
            self.RCMP_remote_console_session_id = PayloadRAKPMessage4.extract_remote_console_session_id(keys['data'])
            self.integrity_check_value = PayloadRAKPMessage4.extract_integrity_check_value(keys['data'])
            self.SIK = None
            self.RCMP_auth_algorithm = None
            self.RAKP_message_1_remote_console_random_number = None
            self.RAKP_message_1_managed_system_session_id = None
            self.RAKP_message_2_managed_system_GUID = None
        elif len(keys) == 8:
            self.RAKP_message_3_message_tag = keys['RAKP_message_3_message_tag']
            self.rcmp_status_code = keys['rcmp_status_code']
            self.reserved = '0000'
            self.RCMP_remote_console_session_id = keys['RCMP_remote_console_session_id']
            self.SIK = keys['SIK']
            self.RCMP_auth_algorithm = keys['RCMP_auth_algorithm']
            self.RAKP_message_1_remote_console_random_number = keys['RAKP_message_1_remote_console_random_number']
            self.RAKP_message_1_managed_system_session_id = keys['RAKP_message_1_managed_system_session_id']
            self.RAKP_message_2_managed_system_GUID = keys['RAKP_message_2_managed_system_GUID']
            self.integrity_check_value = self.calc_integrity_check_value()
            

    def __repr__(self):
        return "------- PayloadRAKPMessage4 -------" \
                + "\nRAKP_message_3_message_tag : " + self.RAKP_message_3_message_tag \
                + "\nrcmp_status_code : " + self.rcmp_status_code + " human readable : " + IPMIHelper.get_rcmp_status_code_definition(self.rcmp_status_code) \
                + "\nreserved : " + self.reserved \
                + "\nmgmt_console_session_id : " + self.RCMP_remote_console_session_id \
                + "\nSIK : " + str(self.SIK) \
                + "\nRCMP_auth_algorithm : " + str(self.RCMP_auth_algorithm) \
                + "\nRAKP_message_1_remote_console_random_number : " + str(self.RAKP_message_1_remote_console_random_number) \
                + "\nRAKP_message_1_managed_system_session_id : " + str(self.RAKP_message_1_managed_system_session_id) \
                + "\nRAKP_message_2_managed_system_GUID : " + str(self.RAKP_message_2_managed_system_GUID) \
                + "\nintegrity_check_value : " + self.integrity_check_value
 
    @staticmethod
    def extract_message_tag(data):
        return data[0:2]

    @staticmethod
    def extract_rcmp_status_code(data):
        return data[2:4]

    @staticmethod
    def extract_reserved(data):
        return data[4:8]

    @staticmethod
    def extract_remote_console_session_id(data):
        return data[8:16]

    @staticmethod
    def extract_integrity_check_value(data):
        return data[16:]

    def calc_integrity_check_value(self):
        if self.RCMP_auth_algorithm == 'RAKP-HMAC-SHA1':
            #test = self.RAKP_message_1_remote_console_random_number + self.RAKP_message_1_managed_system_session_id + self.RAKP_message_2_managed_system_GUID
            hmac_sik = hmac.new(bytes.fromhex(self.SIK)
            , bytes.fromhex(self.RAKP_message_1_remote_console_random_number + self.RAKP_message_1_managed_system_session_id + self.RAKP_message_2_managed_system_GUID)
            , sha1)
        else:
            raise AttributeError('Authentication algorithm ' + str(self.RCMP_auth_algorithm) + ' not implemented')

        return hmac_sik.digest().hex()[0:24]
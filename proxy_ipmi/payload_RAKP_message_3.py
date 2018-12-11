from ipmi_helper import IPMIHelper
import hmac
from hashlib import sha1

class PayloadRAKPMessage3():

    def __init__(self, **keys):

        if len(keys) == 1:
            self.message_tag = PayloadRAKPMessage3.extract_message_tag(keys['data'])
            self.rcmp_status_code = PayloadRAKPMessage3.extract_rcmp_status_code(keys['data'])
            self.reserved = PayloadRAKPMessage3.extract_reserved(keys['data'])
            self.managed_system_session_id = PayloadRAKPMessage3.extract_managed_system_session_id(keys['data'])
            self.key_exchange_auth_code = PayloadRAKPMessage3.extract_key_exchange_auth_code(keys['data'])
            self.RCMP_auth_algorithm = None
            self.RAKP_message_2_managed_system_random_number = None
            self.RCMP_remote_console_session_id = None
            self.RAKP_message_1_requested_max_privilege = None
            self.RAKP_message_1_user_name_length = None
            self.RAKP_message_1_user_name = None
            self.associated_user_password = None
        elif len(keys) == 10:
            self.message_tag = keys['message_tag']
            self.rcmp_status_code = keys['rcmp_status_code']
            self.reserved = '0000'
            self.managed_system_session_id = keys['managed_system_session_id']
            self.RCMP_auth_algorithm = keys['RCMP_auth_algorithm']
            self.RAKP_message_2_managed_system_random_number = keys['RAKP_message_2_managed_system_random_number']
            self.RCMP_remote_console_session_id = keys['RCMP_remote_console_session_id']
            self.RAKP_message_1_requested_max_privilege = keys['RAKP_message_1_requested_max_privilege']
            self.RAKP_message_1_user_name_length = keys['RAKP_message_1_user_name_length']
            self.RAKP_message_1_user_name = keys['RAKP_message_1_user_name']
            self.associated_user_password = keys['associated_user_password']
            self.key_exchange_auth_code = self.calc_hmac_kuid()
        else:
            raise ValueError("No constructor with " + str(len(keys)) + " arguments.") 

    def __repr__(self):
        return "------- PayloadRAKPMessage3 -------" \
                + "\nmessage_tag : " + self.message_tag \
                + "\nrcmp_status_code : " + self.rcmp_status_code + " human readable : " + IPMIHelper.get_rcmp_status_code_definition(self.rcmp_status_code) \
                + "\nreserved : " + self.reserved \
                + "\nmanaged_system_session_id : " + self.managed_system_session_id \
                + "\nRCMP_auth_algorithm : " + str(self.RCMP_auth_algorithm) \
                + "\nRAKP_message_2_managed_system_random_number : " + str(self.RAKP_message_2_managed_system_random_number) \
                + "\nRCMP_remote_console_session_id : " + str(self.RCMP_remote_console_session_id) \
                + "\nRAKP_message_1_requested_max_privilege : " + str(self.RAKP_message_1_requested_max_privilege) \
                + "\nRAKP_message_1_user_name_length : " + str(self.RAKP_message_1_user_name_length) \
                + "\nRAKP_message_1_user_name : " + str(self.RAKP_message_1_user_name) \
                + "\nassociated_user_password : " + str(self.associated_user_password) \
                + "\nkey_exchange_auth_code : " + self.key_exchange_auth_code
 
    def serialize(self):
        return self.message_tag \
                + self.rcmp_status_code \
                + self.reserved \
                + self.managed_system_session_id \
                + self.key_exchange_auth_code

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
    def extract_managed_system_session_id(data):
        return data[8:16]

    @staticmethod
    def extract_key_exchange_auth_code(data):
        return data[16:]

    def calc_hmac_kuid(self):
        if self.RCMP_auth_algorithm == 'RAKP-HMAC-SHA1':
            datas_to_hash = self.RAKP_message_2_managed_system_random_number + self.RCMP_remote_console_session_id + self.RAKP_message_1_requested_max_privilege + self.RAKP_message_1_user_name_length + self.RAKP_message_1_user_name
            hmac_kuid = hmac.new(self.associated_user_password.encode()
            , bytes.fromhex(str(datas_to_hash))
            , sha1)
        else:
            raise AttributeError('Authentication algorithm ' + str(self.RCMP_auth_algorithm) + ' not implemented')

        return hmac_kuid.digest().hex()

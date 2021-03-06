from ipmi_helper import IPMIHelper
from hashlib import sha1
import hmac
import random
import uuid

class PayloadRAKPMessage2():

    def __init__(self, **keys):

        if len(keys) == 1:
            self.RAKP_message_1_message_tag = PayloadRAKPMessage2.extract_message_tag(keys['data'])
            self.rcmp_status_code = PayloadRAKPMessage2.extract_rcmp_status_code(keys['data'])
            self.reserved = PayloadRAKPMessage2.extract_reserved(keys['data'])
            self.RCMP_remote_console_session_id = PayloadRAKPMessage2.extract_remote_console_session_id(keys['data'])
            self.managed_system_random_number = PayloadRAKPMessage2.extract_managed_system_random_number(keys['data'])
            self.managed_system_GUID = PayloadRAKPMessage2.extract_managed_system_GUID(keys['data'])
            self.RAKP_message_1_managed_system_session_id = None
            self.RAKP_message_1_remote_console_random_number = None
            self.RAKP_message_1_requested_max_privilege = None
            self.RAKP_message_1_user_name_length = None
            self.RAKP_message_1_user_name = None
            self.associated_user_password = None
            self.RCMP_auth_algorithm = None
            self.key_exchange_auth_code = PayloadRAKPMessage2.key_exchange_auth_code(keys['data'])
            self.SIK = None
        elif len(keys) == 10:
            self.RAKP_message_1_message_tag = keys['RAKP_message_1_message_tag']
            self.rcmp_status_code = keys['rcmp_status_code']
            self.reserved = '0000'
            self.RCMP_remote_console_session_id = keys['RCMP_remote_console_session_id']
            self.managed_system_random_number = PayloadRAKPMessage2.generate_managed_system_random_number()
            self.managed_system_GUID = PayloadRAKPMessage2.generate_managed_system_GUID()
            self.RAKP_message_1_managed_system_session_id = keys['RAKP_message_1_managed_system_session_id']
            self.RAKP_message_1_remote_console_random_number = keys['RAKP_message_1_remote_console_random_number']
            self.RAKP_message_1_requested_max_privilege = keys['RAKP_message_1_requested_max_privilege']
            self.RAKP_message_1_user_name_length = keys['RAKP_message_1_user_name_length']
            self.RAKP_message_1_user_name = keys['RAKP_message_1_user_name']
            self.associated_user_password = keys['associated_user_password']
            self.RCMP_auth_algorithm = keys['RCMP_auth_algorithm']
            self.key_exchange_auth_code = self.calc_hmac_kuid()
            self.SIK = self.calc_hmac_SIK()
        else:
            AttributeError('No constructor exists for PayloadRAKPMessage2 with ' + len(keys) + " parameters.")

    def __repr__(self):
        return "------- PayloadRAKPMessage2 -------" \
                + "\nRAKP_message_1_message_tag : " + self.RAKP_message_1_message_tag \
                + "\nrcmp_status_code : " + self.rcmp_status_code + " human readable : " + PayloadRAKPMessage2.get_rcmp_status_code_definition(self.rcmp_status_code) \
                + "\nreserved : " + self.reserved \
                + "\nRCMP_remote_console_session_id : " + self.RCMP_remote_console_session_id \
                + "\nmanaged_system_random_number : " + self.managed_system_random_number \
                + "\nmanaged_system_GUID : " + self.managed_system_GUID \
                + "\nRAKP_message_1_managed_system_session_id : " + str(self.RAKP_message_1_managed_system_session_id) \
                + "\nRAKP_message_1_remote_console_random_number : " + str(self.RAKP_message_1_remote_console_random_number) \
                + "\nRAKP_message_1_requested_max_privilege : " + str(self.RAKP_message_1_requested_max_privilege) \
                + "\nRAKP_message_1_user_name_length : " + str(self.RAKP_message_1_user_name_length) \
                + "\nRAKP_message_1_user_name : " + str(self.RAKP_message_1_user_name) \
                + "\nassociated_user_password : " + str(self.associated_user_password) \
                + "\nRCMP_auth_algorithm : " + str(self.RCMP_auth_algorithm) \
                + "\nkey_exchange_auth_code : " + self.key_exchange_auth_code \
                + "\nSIK : " + str(self.SIK)
 
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
    def extract_managed_system_random_number(data):
        return data[16:48]

    @staticmethod
    def extract_managed_system_GUID(data):
        return data[48:80]

    @staticmethod
    def key_exchange_auth_code(data):
        return data[80:]

    @staticmethod
    def get_rcmp_status_code_definition(hex_val):
        maximum_privileges = {
            '00' :'No errors',
            '01' : 'Insufficient resources to create a session',
            '02' : 'Invalid session ID',
            '03' : 'Invalid payload type',
            '04' : 'Invalid authentication algorithm',
            '05' : 'Invalid integrity algorithm',
            '06' : 'No matching authentication payload',
            '07' : 'No matching integrity payload',
            '08' : 'Inactive session id',
            '09' : 'Invalid role',
            '0a' : 'Unauthorized role or privilege level requested',
            '0b' : 'Insufficient resources to create a session at the requested role',
            '0c' : 'Invalid name length',
            '0d' : 'Unauthorized name',
            '0e' : 'Unauthorized GUID',
            '0f' : 'Invalid integrity check value',
            '10' : 'Invalid confidentiality algorithm',
            '11' : 'No Cipher suite match with proposed security algorithm',
            '12' : 'Illegal or unrecognized parameter'
        }

        try:
            return maximum_privileges[hex_val]
        except:
            return "Reserved for future definition"

    @staticmethod
    def generate_managed_system_random_number():
        lower_bound = 0
        upper_bound = int('FF'*16, 16)

        random_number = random.randint(lower_bound, upper_bound)

        return hex(random_number)[2:]


    @staticmethod
    def generate_managed_system_GUID():
        return uuid.uuid4().hex

    def calc_hmac_kuid(self):
        if self.RCMP_auth_algorithm == 'RAKP-HMAC-SHA1':
            datas_to_hash = self.RCMP_remote_console_session_id + self.RAKP_message_1_managed_system_session_id + self.RAKP_message_1_remote_console_random_number + self.managed_system_random_number + self.managed_system_GUID + self.RAKP_message_1_requested_max_privilege + self.RAKP_message_1_user_name_length + self.RAKP_message_1_user_name
            hmac_kuid = hmac.new(self.associated_user_password.encode()
            , bytes.fromhex(str(datas_to_hash))
            , sha1)
        else:
            raise AttributeError('Authentication algorithm ' + str(self.RCMP_auth_algorithm) + ' not implemented')

        return hmac_kuid.digest().hex()

    def calc_hmac_SIK(self):
        if self.RCMP_auth_algorithm == 'RAKP-HMAC-SHA1':
            #test = self.RAKP_message_1_remote_console_random_number + self.managed_system_random_number + self.RAKP_message_1_requested_max_privilege + self.RAKP_message_1_user_name_length + self.RAKP_message_1_user_name
            password_hex_length = len(self.associated_user_password.encode().hex())
            if password_hex_length < 16:
                padded_hex_password = self.associated_user_password.encode().hex() + '00' * (16-password_hex_length)
            else:
                padded_hex_password = self.associated_user_password.encode().hex()
            hmac_sik = hmac.new(bytes.fromhex(padded_hex_password)
            , bytes.fromhex(self.RAKP_message_1_remote_console_random_number + self.managed_system_random_number + self.RAKP_message_1_requested_max_privilege + self.RAKP_message_1_user_name_length + self.RAKP_message_1_user_name)
            , sha1)
        else:
            raise AttributeError('Authentication algorithm ' + self.RCMP_auth_algorithm + ' not implemented')

        return hmac_sik.digest().hex()
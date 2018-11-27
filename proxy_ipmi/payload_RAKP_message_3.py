from ipmi_helper import IPMIHelper

class PayloadRAKPMessage3():

    def __init__(self, **keys):

        if len(keys) == 1:
            self.message_tag = PayloadRAKPMessage3.extract_message_tag(keys['data'])
            self.rcmp_status_code = PayloadRAKPMessage3.extract_rcmp_status_code(keys['data'])
            self.reserved = PayloadRAKPMessage3.extract_reserved(keys['data'])
            self.managed_system_session_id = PayloadRAKPMessage3.extract_managed_system_session_id(keys['data'])
            self.key_exchange_auth_code = PayloadRAKPMessage3.extract_key_exchange_auth_code(keys['data'])
        elif len(keys) == 5:
            self.message_tag = keys['message_tag']
            self.rcmp_status_code = keys['rcmp_status_code']
            self.reserved = keys['reserved']
            self.managed_system_session_id = keys['managed_system_session_id']
            self.key_exchange_auth_code = keys['key_exchange_auth_code']
        else:
            raise ValueError("No constructor with " + str(len(keys)) + " arguments.") 

    def __repr__(self):
        return "------- PayloadRAKPMessage3 -------" \
                + "\nmessage_tag : " + self.message_tag \
                + "\nrcmp_status_code : " + self.rcmp_status_code + " human readable : " + IPMIHelper.get_rcmp_status_code_definition(self.rcmp_status_code) \
                + "\nreserved : " + self.reserved \
                + "\nmanaged_system_session_id : " + self.managed_system_session_id \
                + "\nkey_exchange_auth_code : " + self.key_exchange_auth_code
 
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

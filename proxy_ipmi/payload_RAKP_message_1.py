from ipmi_helper import IPMIHelper

class PayloadRAKPMessage1():

    def __init__(self, **keys):
        if len(keys) == 1:
            self.message_tag = PayloadRAKPMessage1.extract_message_tag(keys['data'])
            self.reserved = PayloadRAKPMessage1.extract_reserved(keys['data'])
            self.managed_system_session_id = PayloadRAKPMessage1.extract_managed_system_session_id(keys['data'])
            self.remote_console_random_number = PayloadRAKPMessage1.extract_remote_console_random_number(keys['data'])
            self.requested_max_privilege = PayloadRAKPMessage1.extract_requested_max_privilege(keys['data'])
            self.reserved2 = PayloadRAKPMessage1.extract_reserved2(keys['data'])
            self.user_name_length = PayloadRAKPMessage1.extract_user_name_length(keys['data'])
            self.user_name = PayloadRAKPMessage1.extract_user_name(keys['data'])
        elif len(keys) == 4:
            self.message_tag = '00'
            self.reserved = '000000'
            self.managed_system_session_id = PayloadRAKPMessage1.extract_managed_system_session_id(keys['rcmp_open_session_response_managed_system_session_id'])
            self.remote_console_random_number = IPMIHelper.generate_rakp_remote_console_random_number()
            self.requested_max_privilege = PayloadRAKPMessage1.extract_requested_max_privilege(keys['requested_max_privilege'])
            self.reserved2 = '0000'
            self.user_name_length = PayloadRAKPMessage1.extract_user_name_length(keys['user_name_length'])
            self.user_name = PayloadRAKPMessage1.extract_user_name(keys['user_name'])
        

    def __repr__(self):
        return "------- PayloadRAKPMessage1 -------" \
                + "\nmessage_tag : " + self.message_tag \
                + "\nreserved : " + self.reserved \
                + "\nmanaged_system_session_id : " + self.managed_system_session_id \
                + "\nremote_console_random_number : " + self.remote_console_random_number \
                + "\nrequested_max_privilege : " + self.requested_max_privilege \
                + "\n  requested_max_privilege_type : " + self.get_requested_max_privilege_type() \
                + "\n  requested_max_privilege_level : " + self.get_requested_max_privilege_level() + " human readable : " + IPMIHelper.get_requested_max_privilege_level_definition(self.get_requested_max_privilege_level()) \
                + "\nreserved2 : " + self.reserved2 \
                + "\nuser_name_length : " + self.user_name_length \
                + "\nuser_name : " + self.user_name + " human readable : " + IPMIHelper.get_username_human_readable(self.user_name)

    @staticmethod
    def extract_message_tag(data):
        return data[0:2]

    @staticmethod
    def extract_reserved(data):
        return data[2:8]

    @staticmethod
    def extract_managed_system_session_id(data):
        return data[8:16]

    @staticmethod
    def extract_remote_console_random_number(data):
        return data[16:48]

    @staticmethod
    def extract_requested_max_privilege(data):
        return data[48:50]

    @staticmethod
    def extract_reserved2(data):
        return data[50:54]
    
    @staticmethod
    def extract_user_name_length(data):
        return data[54:56]

    @staticmethod
    def extract_user_name(data):
        return data[56:]

    def get_requested_max_privilege_type(self):
        max_privilege_type = self.requested_max_privilege
        bits = IPMIHelper.get_bits(max_privilege_type)
        max_privilege_type_bit = bits[4]
        return max_privilege_type_bit

    def get_requested_max_privilege_level(self):
        max_privilege_level = self.requested_max_privilege
        bits = IPMIHelper.get_bits(max_privilege_level)
        max_privilege_level_bits = bits[0:3]
        return "".join(max_privilege_level_bits[::-1])


from ipmi_helper import IPMIHelper

class PayloadRMCPOpenSessionResponse():

    def __init__(self, **keys):

        if len(keys) == 1:
            self.message_tag = PayloadRMCPOpenSessionResponse.extract_message_tag(keys['data'])
            self.rmcp_status_code = PayloadRMCPOpenSessionResponse.extract_rmcp_status_code(keys['data'])
            self.max_privilege_level = PayloadRMCPOpenSessionResponse.extract_max_privilege_level(keys['data'])
            self.reserved = PayloadRMCPOpenSessionResponse.extract_reserved(keys['data'])
            self.remote_console_session_id = PayloadRMCPOpenSessionResponse.extract_remote_console_session_id(keys['data'])
            self.managed_system_session_id = PayloadRMCPOpenSessionResponse.extract_managed_system_session_id(keys['data'])
            self.auth_payload = PayloadRMCPOpenSessionResponse.extract_auth_payload(keys['data'])
            self.integrity_payload = PayloadRMCPOpenSessionResponse.extract_integrity_payload(keys['data'])
            self.confidentiality_payload = PayloadRMCPOpenSessionResponse.extract_confidentiality_payload(keys['data'])
        elif len(keys) == 7:
            self.message_tag = keys['message_tag']
            self.rmcp_status_code = keys['rmcp_status_code']
            self.max_privilege_level = keys['max_privilege_level']
            self.reserved = '00'
            self.remote_console_session_id = keys['remote_console_session_id']
            self.managed_system_session_id = IPMIHelper.generate_managed_system_session_id()
            self.auth_payload = keys['auth_payload']
            self.integrity_payload = keys['integrity_payload']
            self.confidentiality_payload = keys['confidentiality_payload']
        else:
            raise ValueError("No constructor with " + str(len(keys)) + " arguments.") 

    def __repr__(self):
        return "------- PayloadRMCPOpenSessionResponse -------" \
                + "\nmessage_tag : " + self.message_tag \
                + "\nrmcp_status_code : " + self.rmcp_status_code \
                + "\nmax_privilege_level : " + self.max_privilege_level + " human readable : " + IPMIHelper.get_requested_maximum_privilege_definition(self.max_privilege_level) \
                + "\nreserved : " + self.reserved \
                + "\nremote_console_session_id : " + self.remote_console_session_id \
                + "\nmanaged_system_session_id : " + self.managed_system_session_id \
                + "\nauth_payload : " + self.auth_payload \
                + "\n  auth_payload_type : " + self.get_auth_payload_type() \
                + "\n  auth_payload_length : " + self.get_auth_payload_length() \
                + "\n  auth_payload_auth_algo : " + self.get_auth_payload_auth_algo() + " human readable : " + IPMIHelper.get_auth_algorithm_definition(self.get_auth_payload_auth_algo()) \
                + "\nintegrity_payload : " +  self.integrity_payload \
                + "\n  integrity_payload_type : " +  self.get_integrity_payload_type() \
                + "\n  integrity_payload_length : " + self.get_integrity_payload_length() \
                + "\n  integrity_payload_integrity_algo : " + self.get_integrity_payload_integrity_algo() + " human readable : " + IPMIHelper.get_integrity_algorithm_definition(self.get_integrity_payload_integrity_algo()) \
                + "\nconfidentiality_payload : " + self.confidentiality_payload \
                + "\n  confidentiality_payload_type : " + self.get_confidentiality_payload_type() \
                + "\n  confidentiality_payload_length : " + self.get_confidentiality_payload_length() \
                + "\n  confidentiality_payload_confidentiality_algo : " + self.get_confidentiality_payload_integrity_algo() + " human readable : " + IPMIHelper.get_confidentiality_algorithm_definition(self.get_confidentiality_payload_integrity_algo()) \

    def serialize(self):
        return self.message_tag + self.rmcp_status_code + self.max_privilege_level + self.reserved + self.remote_console_session_id + self.managed_system_session_id + self.auth_payload + self.integrity_payload + self.confidentiality_payload

    @staticmethod
    def extract_message_tag(data):
        return data[0:2]

    @staticmethod
    def extract_rmcp_status_code(data):
        return data[2:4]
    
    @staticmethod
    def extract_max_privilege_level(data):
        return data[4:6]

    @staticmethod
    def extract_reserved(data):
        return data[6:8]
    
    @staticmethod
    def extract_remote_console_session_id(data):
        return data[8:16]

    @staticmethod
    def extract_managed_system_session_id(data):
        return data[16:24]

    @staticmethod
    def extract_auth_payload(data):
        return data[24:40]

    @staticmethod
    def extract_integrity_payload(data):
        return data[40:56]
    
    @staticmethod
    def extract_confidentiality_payload(data):
        return data[56:72]

    def get_auth_payload_type(self):
        return self.auth_payload[0:2]

    def get_auth_payload_length(self):
        return self.auth_payload[6:8]

    def get_auth_payload_auth_algo(self):
        byte_hex = self.auth_payload[8:10]
        bits = IPMIHelper.get_bits(byte_hex)
        auth_algorithm = bits[0:5]
        return "".join(auth_algorithm[::-1])

    def get_integrity_payload_type(self):
        return self.integrity_payload[0:2]

    def get_integrity_payload_length(self):
        return self.integrity_payload[6:8]

    def get_integrity_payload_integrity_algo(self):
        byte_hex = self.integrity_payload[8:10]
        bits = IPMIHelper.get_bits(byte_hex)
        auth_algorithm = bits[0:5]
        return "".join(auth_algorithm[::-1])

    def get_confidentiality_payload_type(self):
        return self.confidentiality_payload[0:2]

    def get_confidentiality_payload_length(self):
        return self.confidentiality_payload[6:8]

    def get_confidentiality_payload_integrity_algo(self):
        byte_hex = self.confidentiality_payload[8:10]
        bits = IPMIHelper.get_bits(byte_hex)
        auth_algorithm = bits[0:5]
        return "".join(auth_algorithm[::-1])

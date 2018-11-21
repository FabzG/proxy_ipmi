from ipmi_helper import IPMIHelper

class PayloadRMCPOpenSessionRequest():

    def __init__(self, data):
        self.message_tag = PayloadRMCPOpenSessionRequest.extract_message_tag(data)
        self.requested_max_privilege = PayloadRMCPOpenSessionRequest.extract_requested_max_privilege(data)
        self.reserved = PayloadRMCPOpenSessionRequest.extract_reserved(data)
        self.remote_console_session_id = PayloadRMCPOpenSessionRequest.extract_remote_console_session_id(data)
        self.auth_payload = PayloadRMCPOpenSessionRequest.extract_auth_payload(data)
        self.integrity_payload = PayloadRMCPOpenSessionRequest.extract_integrity_payload(data)
        self.confidentiality_payload = PayloadRMCPOpenSessionRequest.extract_confidentiality_payload(data)

    def __repr__(self):
        return "------- PayloadRMCPOpenSessionRequest -------" \
                + "\nmessage_tag : " + self.message_tag \
                + "\nrequested_max_privilege : " + self.requested_max_privilege + " human readable : " + PayloadRMCPOpenSessionRequest.get_requested_maximum_privilege_definition(self.requested_max_privilege) \
                + "\nreserved : " + self.reserved \
                + "\nremote_console_session_id : " + self.remote_console_session_id \
                + "\nauth_payload : " + self.auth_payload \
                + "\n  auth_payload_type : " + self.get_auth_payload_type() \
                + "\n  auth_payload_length : " + self.get_auth_payload_length() \
                + "\n  auth_payload_auth_algo : " + self.get_auth_payload_auth_algo() + " human readable : " + PayloadRMCPOpenSessionRequest.get_auth_algorithm_definition(self.get_auth_payload_auth_algo()) \
                + "\nintegrity_payload : " +  self.integrity_payload \
                + "\n  integrity_payload_type : " +  self.get_integrity_payload_type() \
                + "\n  integrity_payload_length : " + self.get_integrity_payload_length() \
                + "\n  integrity_payload_integrity_algo : " + self.get_integrity_payload_integrity_algo() + " human readable : " + PayloadRMCPOpenSessionRequest.get_integrity_algorithm_definition(self.get_integrity_payload_integrity_algo()) \
                + "\nconfidentiality_payload : " + self.confidentiality_payload \
                + "\n  confidentiality_payload_type : " + self.get_confidentiality_payload_type() \
                + "\n  confidentiality_payload_length : " + self.get_confidentiality_payload_length() \
                + "\n  confidentiality_payload_confidentiality_algo : " + self.get_confidentiality_payload_integrity_algo() + " human readable : " + PayloadRMCPOpenSessionRequest.get_confidentiality_algorithm_definition(self.get_confidentiality_payload_integrity_algo()) \

    @staticmethod
    def extract_message_tag(data):
        return data[0:2]

    @staticmethod
    def extract_requested_max_privilege(data):
        return data[2:4]

    @staticmethod
    def extract_reserved(data):
        return data[4:8]
    
    @staticmethod
    def extract_remote_console_session_id(data):
        return data[8:16]

    @staticmethod
    def extract_auth_payload(data):
        return data[16:32]

    @staticmethod
    def extract_integrity_payload(data):
        return data[32:48]
    
    @staticmethod
    def extract_confidentiality_payload(data):
        return data[48:64]

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

    @staticmethod
    def get_requested_maximum_privilege_definition(hex_val):
        maximum_privileges = {
            '00' :'Highest level matching proposed algorithms',
            '01' : 'CALLBACK level',
            '02' : 'USER level',
            '03' : 'OPERATOR level',
            '04' : 'ADMINISTRATOR level',
            '05' : 'OEM Proprietary level'
        }

        try:
            return maximum_privileges[hex_val]
        except:
            return "Unkown level"

    @staticmethod
    def get_auth_algorithm_definition(bits_string_val):
        int_val = int(bits_string_val, 2)

        if int_val == 0:
            return "RAKP-none"
        elif int_val == 1:
            return "RAKP-HMAC-SHA1"
        elif int_val == 2:
            return "RAKP-HMAC-MD5"
        elif int_val == 3:
            return "RAKP-HMAC-SHA256"
        elif int_val >= 192 and int_val <= 255:
            return "OEM"
        else:
            return "reserved"

    @staticmethod
    def get_integrity_algorithm_definition(bits_string_val):
        int_val = int(bits_string_val, 2)

        if int_val == 0:
            return "none"
        elif int_val == 1:
            return "HMAC-SHA1-96"
        elif int_val == 2:
            return "HMAC-MD5-128"
        elif int_val == 3:
            return "MD5-128"
        elif int_val == 4:
            return "HMAC-SHA256-128"
        elif int_val >= 192 and int_val <= 255:
            return "OEM"
        else:
            return "reserved"

    @staticmethod
    def get_confidentiality_algorithm_definition(bits_string_val):
        int_val = int(bits_string_val, 2)

        if int_val == 0:
            return "none"
        elif int_val == 1:
            return "AES-CBC-128"
        elif int_val == 2:
            return "xRC4-128"
        elif int_val == 3:
            return "xRC4-40"
        elif int_val >= 48 and int_val <= 63:
            return "OEM"
        else:
            return "reserved"
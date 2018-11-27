from Crypto.Cipher import AES
from rmcp_message import RMCPMessage
import math

class IPMILanMessage(RMCPMessage):

    def __init__(self, **keys):
        if len(keys) == 1:
            self.ipmi_auth_type = self.extract_auth_type(keys['data'])
            self.ipmi_session_seq_number = self.extract_session_seq_number(keys['data']) #==managed_system_session_id reversed hex mode
            self.ipmi_session_id = self.extract_session_id(keys['data'])
            self.ipmi_msg_lenght = self.extract_msg_lenght(keys['data'])
            self.ipmi_remaining_message = self.extract_ipmi_remaining_message(keys['data'])
        elif len(keys) == 5:
            self.ipmi_auth_type = keys['ipmi_auth_type']
            self.ipmi_session_seq_number = keys['ipmi_session_seq_number']
            self.ipmi_session_id = keys['ipmi_session_id']
            self.ipmi_msg_lenght = keys['ipmi_msg_lenght']
            self.ipmi_remaining_message = keys['ipmi_remaining_message']
        else:
            raise ValueError("No constructor with " + str(len(keys)) + " arguments.") 


        def extract_auth_type(self):
            pass
        def extract_session_seq_number(self):

        def extract_session_id(self):

        def extract_msg_lenght(self):
        
        def extract_ipmi_remaining_message(self):
from ipmi_helper import IPMIHelper

class IPMISession ():

    def __init__(self, session_ïd):
        self.session_id = session_ïd
        self.session_sequence = IPMISession.init_sequence_number()
        #RAKP_message_1_message_tag
        self.RAKP_message_1_remote_console_random_number = None
        #RAKP_message_1_requested_max_privilege
        #RAKP_message_1_user_name_length
        #RAKP_message_1_user_name
        self.password = None
        self.auth_algorithm = None
        self.RAKP_message_2_managed_system_GUID = None
        #RAKP_message_3_message_tag
        self.SIK = None
        
    @staticmethod
    def init_sequence_number():
        first_sequence_number = IPMIHelper.invert_hex('00000001')
        return first_sequence_number
    
    def increment_sequence_number(self):
        current_sequence_number = IPMIHelper.invert_hex(self.session_sequence)
        
        int_sequence_number = int(current_sequence_number, 16)

        hex_inc_seq = hex(int_sequence_number+1)[2:]

        delta_size = int(4 - len(hex_inc_seq))

        hex_inc_seq = '00'*delta_size + hex_inc_seq

        return IPMIHelper.invert_hex(hex_inc_seq)

    def get_remote_console_session_id(self):
        return self.session_id[:8]

    def get_managed_system_session_id(self):
        return self.session_id[8:]
        
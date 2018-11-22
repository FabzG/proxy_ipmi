from ipmi_1_5_no_auth import IPMI15SessionWrapper
from ipmi_2_0_no_trail import IPMI20NoTrailWrapper
from ipmi_2_0_trail import IPMI20TrailWrapper
from Crypto.Cipher import AES
import math

class IPMISessionWrapper():

    @staticmethod
    def guess_version(data):
        
        if IPMISessionWrapper.is_v15_without_auth_code(data):
            return "V15_no_authcode"
        elif IPMISessionWrapper.is_v20_without_trailing(data):
            return "V20_no_trailing"
        elif IPMISessionWrapper.is_v20_with_trailing(data):
            return "V20_trailing"
        else:
            raise AttributeError("Unrcognized IPMI version.")

    @staticmethod
    def is_v15_without_auth_code(data):
        auth_type = data[0:2]
        msg_length = data[18:20]
        if len(data[20:])/2 == int(msg_length, 16) and auth_type == '00':
            return True
        return False
    
    @staticmethod
    def is_v20_without_trailing(data):
        auth_type = auth_type = data[0:2]
        msg_length = data[20:24]
        if len(data[24:])/2 == int(msg_length[0:2], 16) and auth_type == '06':
            return True
        return False

    @staticmethod
    def is_v20_with_trailing(data):
        auth_type = auth_type = data[0:2]
        msg_length = data[20:24]
        trailing_msg = data[24+int(msg_length[0:2], 16)*2:]
        nb_pad = 0

        for index, pad in enumerate(trailing_msg):
            if pad == 'f' and trailing_msg[index+1]:
                nb_pad = nb_pad + 1
            else:
                if nb_pad % 2 == 0 and int(trailing_msg[index:index+2], 16) == nb_pad / 2:
                    break
                else:
                    return False

        if len(trailing_msg) > 0 and auth_type == '06':
            return True

        return False
    
    @staticmethod
    def get_IPMI_message_instance(data):
        ipmi_version = IPMISessionWrapper.guess_version(data)

        if ipmi_version == "V15_no_authcode":
            return IPMI15SessionWrapper(data = data)
        elif ipmi_version == "V20_no_trailing":
            return IPMI20NoTrailWrapper(data = data)
        elif ipmi_version == "V20_trailing":
            return IPMI20TrailWrapper(data = data)
        else:
            raise AttributeError("Unrcognized IPMI version.")

'''
print(IPMI_wrapper.is_v15_without_auth_code('000000000000000000092018c88110388e03a6'))
print(IPMI_wrapper.is_v15_without_auth_code('00000000000000000010811c632010380001840403000000000c'))
print(IPMI_wrapper.is_v15_without_auth_code('061000000000000000002000150300008a0a30d7000000080100000001000008010000000200000801000000'))
print(IPMI_wrapper.is_v20_without_trailing('061000000000000000002000150300008a0a30d7000000080100000001000008010000000200000801000000'))
print(IPMI_wrapper.is_v20_with_trailing('061000000000000000002000150300008a0a30d7000000080100000001000008010000000200000801000000'))
print(IPMI_wrapper.is_v20_with_trailing('06c09a3dfeeb0200000020002bbeba34c433ffe01418fbbc6af98458f0d17b1003363a316334211f4ded488cffff0207b6b9cdbaad54715d44c32adf'))


test = IPMI_wrapper('000000000000000000092018c88110388e03a6')
print(test.ipmi_object.ipmi_auth_type)
print(test.ipmi_object.ipmi_payload_encrypted)
print(test.ipmi_object.ipmi_payload_authentication)
print(test.ipmi_object.ipmi_payload_type)
print(test.ipmi_object.ipmi_session_seq)
print(test.ipmi_object.ipmi_session_id)
print(test.ipmi_object.message_length)
print(test.ipmi_object.message_content)
print(test.ipmi_object.trailer)
'''
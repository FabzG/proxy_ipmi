from payload_ipmi_lan_req_msg import IPMILanRequest
from payload_ipmi_lan_resp_msg import IPMILanResponse
from payload_rmcp_open_session_req import PayloadRMCPOpenSessionRequest
from payload_rmcp_open_session_resp import PayloadRMCPOpenSessionResponse
from payload_RAKP_message_1 import PayloadRAKPMessage1
from payload_RAKP_message_2 import PayloadRAKPMessage2
from payload_RAKP_message_3 import PayloadRAKPMessage3
from payload_RAKP_message_4 import PayloadRAKPMessage4
#from ipmi_lan_req_msg import IPMILanRequestMessage
#from ipmi_lan_resp_msg import IPMILanResponseMessage
from Crypto.Cipher import AES
from ipmi_helper import IPMIHelper
import math

class IPMIContentWrapper():

    def __init__(self, payload_type, data):
        self.ipmi_content_object = self.get_IPMI_content_instance(payload_type, data)


    @staticmethod
    def get_IPMI_content_instance(payload_type, data):
        if payload_type == "IPMI Message":
            return PayloadIPMIMessage(data)
        elif payload_type == "RMCP+ Open Session Request":
            return PayloadRMCPOpenSessionRequest(data=data)
        elif payload_type == "RMCP+ Open Session Response":
            return PayloadRMCPOpenSessionResponse(data=data)
        elif payload_type == "RAKP Message 1":
            return PayloadRAKPMessage1(data = data)
        elif payload_type == "RAKP Message 2":
            return PayloadRAKPMessage2(data = data)
        elif payload_type == "RAKP Message 3":
            return PayloadRAKPMessage3(data = data)
        elif payload_type == "RAKP Message 4":
            return PayloadRAKPMessage4(data = data)
        elif payload_type == "IPMI v1.5 payload":
            return PayloadIPMIv15(data = data)
        elif payload_type == "SOL (serial over LAN)":
            raise AttributeError("Message type SOL is not supported.")
        elif payload_type == "OEM Explicit":
            raise AttributeError("Message type OEM explicit is not supported.")
        elif payload_type == "OEM Payload":
            raise AttributeError("Message type OEM Payload is not supported.")
        else:
            raise AttributeError("Unrcognized IPMI payload type.")

'''
test = IPMIContentWrapper("IPMI v1.5 payload", '2018c88110388e03a6')
print(test.ipmi_content_object)

test = PayloadIPMIv15(rsAddr='20', netFn='011000', rsLUN='00', rqAddr='81', rqSeq='001000', rqLUN='00', command='38', request_data='8e03')
print(test)

test = IPMIContentWrapper("RMCP+ Open Session Request", '150300008a0a30d7000000080100000001000008010000000200000801000000')
print(test.ipmi_content_object)

test = IPMIContentWrapper("RMCP+ Open Session Response", '150003008a0a30d79a3dfeeb000000080100000801000008010000080200000801ff0207')
print(test.ipmi_content_object)

test = IPMIContentWrapper("RAKP Message 1", '160000009a3dfeeb9d40baa3db2c02cd89d05508994672d6130000046d616173')
print(test.ipmi_content_object)

#pass : 3C7QT5FYzFVxL
test = IPMIContentWrapper("RAKP Message 2", '160000008a0a30d722b92cc2a698feb06443eb4dbddfe27d7f6d88002ab511e58000001e67ec57caf87ba669e0e2aeb1688ec82765072818bcbce79d')
print(test.ipmi_content_object)
test.ipmi_content_object.RAKP_message_1_managed_system_session_id = '9a3dfeeb'
test.ipmi_content_object.RAKP_message_1_remote_console_random_number = '9d40baa3db2c02cd89d05508994672d6'
test.ipmi_content_object.RAKP_message_1_requested_max_privilege = '13'
test.ipmi_content_object.RAKP_message_1_user_name_length = '04'
test.ipmi_content_object.RAKP_message_1_user_name = '6d616173'
test.ipmi_content_object.associated_user_password = '3C7QT5FYzFVxL'
test.ipmi_content_object.RCMP_auth_algorithm = 'RAKP-HMAC-SHA1'
print("ULTIMATE TEST !!!! : " + test.ipmi_content_object.calc_hmac_kuid())
print("ULTIMATE TEST SIK !!!! : " + test.ipmi_content_object.calc_hmac_SIK())
print(test.ipmi_content_object)

test = PayloadRAKPMessage2(RAKP_message_1_message_tag='16', rcmp_status_code='00', RCMP_remote_console_session_id='8a0a30d7', RAKP_message_1_managed_system_session_id='9a3dfeeb' , RAKP_message_1_remote_console_random_number='9d40baa3db2c02cd89d05508994672d6', RAKP_message_1_requested_max_privilege='13', RAKP_message_1_user_name_length='04', RAKP_message_1_user_name='6d616173', associated_user_password='3C7QT5FYzFVxL', RCMP_auth_algorithm='RAKP-HMAC-SHA1')
print("HAHAHAHAHAHAHA\n" + str(test))

test = IPMIContentWrapper("RAKP Message 3", '170000009a3dfeebfdd408c8a93e1770714d8fa5d88775b8f0798e96')
print(test.ipmi_content_object)

test = IPMIContentWrapper("RAKP Message 4", '170000008a0a30d77879acab2d14f1f7758cceb3')
test.ipmi_content_object.RAKP_message_3_message_tag='17'
test.ipmi_content_object.rcmp_status_code='00'
test.ipmi_content_object.RCMP_remote_console_session_id='8a0a30d7'
test.ipmi_content_object.SIK='a81c00dca294467b52e0d087d13ab32f532cf5cc'
test.ipmi_content_object.RAKP_message_1_remote_console_random_number='9d40baa3db2c02cd89d05508994672d6'
test.ipmi_content_object.RAKP_message_1_managed_system_session_id='9a3dfeeb'
test.ipmi_content_object.RAKP_message_2_managed_system_GUID='7f6d88002ab511e58000001e67ec57ca'
test.ipmi_content_object.RCMP_auth_algorithm='RAKP-HMAC-SHA1'
print("ULTIMATE TESTICLE !!!! : " + test.ipmi_content_object.calc_integrity_check_value())
print(test.ipmi_content_object)

test = PayloadRAKPMessage4(RAKP_message_3_message_tag='17', rcmp_status_code='00', RCMP_remote_console_session_id='8a0a30d7', SIK='a81c00dca294467b52e0d087d13ab32f532cf5cc', RAKP_message_1_remote_console_random_number='9d40baa3db2c02cd89d05508994672d6', RAKP_message_1_managed_system_session_id='9a3dfeeb', RAKP_message_2_managed_system_GUID='7f6d88002ab511e58000001e67ec57ca', RCMP_auth_algorithm='RAKP-HMAC-SHA1')
print(test)

test = IPMILanRequestMessage(ciphered_msg='01465379227207e49f73c12dcfe58315800c9defd868a268a51dbd9455110dae', ipmi_sik='a81c00dca294467b52e0d087d13ab32f532cf5cc', RCMP_auth_algorithm='RAKP-HMAC-SHA1')
print(test)

test = IPMILanResponseMessage(ciphered_msg='32750e15e129ec0a5a499b8293d01cb6b689bd053e1acb35c72fbd6f95d96100', ipmi_sik='a81c00dca294467b52e0d087d13ab32f532cf5cc', RCMP_auth_algorithm='RAKP-HMAC-SHA1')
print(test)


test = IPMIContentWrapper("RAKP Message 1", '000000009b52f94903d6d40a9522dbe083834aaac5d6ac1b140000046d616173')
print(test.ipmi_content_object)

test = IPMIContentWrapper("RAKP Message 2", '00000000a4a3a2a047976ac92d5be34dd3ef1f6a7c88116a7f6d88002ab511e58000001e67ec57cad7526ec52928f1726f17f8f824cd518d635b78de')
print(test.ipmi_content_object)
test.ipmi_content_object.RAKP_message_1_managed_system_session_id = '9b52f949'
test.ipmi_content_object.RAKP_message_1_remote_console_random_number = '03d6d40a9522dbe083834aaac5d6ac1b'
test.ipmi_content_object.RAKP_message_1_requested_max_privilege = '14'
test.ipmi_content_object.RAKP_message_1_user_name_length = '04'
test.ipmi_content_object.RAKP_message_1_user_name = '6d616173'
test.ipmi_content_object.associated_user_password = '3C7QT5FYzFVxL'
test.ipmi_content_object.RCMP_auth_algorithm = 'RAKP-HMAC-SHA1'
print("ULTIMATE TEST !!!! : " + test.ipmi_content_object.calc_hmac_kuid())
print("ULTIMATE TEST SIK !!!! : " + test.ipmi_content_object.calc_hmac_SIK())

sik = 'b0027ce44cde097b2ce0bc4ae006a31e24455ae2'

test = IPMILanRequestMessage(ciphered_msg='f7a852ac1ddb8b3da989a7e4fbe7728c1f9903ebb5f8a1549b0f054a1f8c1761', ipmi_sik=sik, RCMP_auth_algorithm='RAKP-HMAC-SHA1')
print("REQ 1\n" + str(test))
test = IPMILanResponseMessage(ciphered_msg='f18230f0380ea4d3a11a8def46368b8da7fd48b7f683f0d567b961d1b957b369', ipmi_sik=sik, RCMP_auth_algorithm='RAKP-HMAC-SHA1')
print("RESP 1\n" + str(test))

test = IPMILanRequestMessage(ciphered_msg='c91f1e7d68cbea569df3d8ff9c3869234157d3668c29625cbdc7e05e819256fa', ipmi_sik=sik, RCMP_auth_algorithm='RAKP-HMAC-SHA1')
print("REQ 2\n" + str(test))
test = IPMILanResponseMessage(ciphered_msg='cdf556fa5139482428678ea4f09f0fe11f935b31c4eabca0efc9d74568b5bc85', ipmi_sik=sik, RCMP_auth_algorithm='RAKP-HMAC-SHA1')
print("RESP 2\n" + str(test))

test = IPMILanRequestMessage(ciphered_msg='957ef52649b9a30e6b99a7c5109a843df16e6a3b14b1b4e274047206aa23d107', ipmi_sik=sik, RCMP_auth_algorithm='RAKP-HMAC-SHA1')
print("REQ 3\n" + str(test))
test = IPMILanResponseMessage(ciphered_msg='223fd15a4d762def90baded6f06964be72ab1b79047822270567a48bf43ca8dedfe3f4595e512648562803c7848e9eff', ipmi_sik=sik, RCMP_auth_algorithm='RAKP-HMAC-SHA1')
print("RESP 3\n" + str(test))

test = IPMILanRequestMessage(ciphered_msg='a9d547fd94b2577595d9ea862e72f5489f38031ac92f4213cf4ad43d7f8bde25', ipmi_sik=sik, RCMP_auth_algorithm='RAKP-HMAC-SHA1')
print("REQ 4\n" + str(test))
test = IPMILanResponseMessage(ciphered_msg='5fbab8b0f400d41c6862c15802d03924a7bc40088fa622f1aeb7c040e64f8a62', ipmi_sik=sik, RCMP_auth_algorithm='RAKP-HMAC-SHA1')
print("RESP 4\n" + str(test))

test = IPMILanRequestMessage(ciphered_msg='9967d7dcd350f4b5f774042ccc989981738dd2226f962b3862101b4e77d78e10', ipmi_sik=sik, RCMP_auth_algorithm='RAKP-HMAC-SHA1')
print("REQ 5\n" + str(test))
test = IPMILanResponseMessage(ciphered_msg='0f0b7e5c81ab4b11652ae856934c14f2a945c610679180bc280e22693cd48f97', ipmi_sik=sik, RCMP_auth_algorithm='RAKP-HMAC-SHA1')
print("RESP 5\n" + str(test))

test = IPMILanRequestMessage(ciphered_msg='0c8bfae78d31d65aed0bd48dece6f23b843e58dc28f7876f3413ed41c49ee289', ipmi_sik=sik, RCMP_auth_algorithm='RAKP-HMAC-SHA1')
print("REQ 6\n" + str(test))
test = IPMILanResponseMessage(ciphered_msg='06cca2facd761735d9d88ddba8c6ffb7cea8a16a26f7e315c1b61a7066257406', ipmi_sik=sik, RCMP_auth_algorithm='RAKP-HMAC-SHA1')
print("RESP 6\n" + str(test))

test = IPMILanRequestMessage(ciphered_msg='028246a31816cb090779a22017c0b1b1ce0773867906bb6bd91d741ba583c763', ipmi_sik=sik, RCMP_auth_algorithm='RAKP-HMAC-SHA1')
print("REQ 7\n" + str(test))
test = IPMILanResponseMessage(ciphered_msg='d17d1352285f648d894ce31c98f70f9ebfd2a538e98b951e2aa8a63028899d2a', ipmi_sik=sik, RCMP_auth_algorithm='RAKP-HMAC-SHA1')
print("RESP 7\n" + str(test))

test = IPMIContentWrapper("RAKP Message 1", '00000000b15cc53dfd8668ba6f24d69b2690b4e75eda5158140000046d616173')
print(test.ipmi_content_object)

test = IPMIContentWrapper("RAKP Message 2", '00000000a4a3a2a0999128b0c6018853dc3019dbe7eb58fa7f6d88002ab511e58000001e67ec57caa9f9334ed4168d539ae26c09675d76eba0a76f62')
print(test.ipmi_content_object)
test.ipmi_content_object.RAKP_message_1_managed_system_session_id = 'b15cc53d'
test.ipmi_content_object.RAKP_message_1_remote_console_random_number = 'fd8668ba6f24d69b2690b4e75eda5158'
test.ipmi_content_object.RAKP_message_1_requested_max_privilege = '14'
test.ipmi_content_object.RAKP_message_1_user_name_length = '04'
test.ipmi_content_object.RAKP_message_1_user_name = '6d616173'
test.ipmi_content_object.associated_user_password = '3C7QT5FYzFVxL'
test.ipmi_content_object.RCMP_auth_algorithm = 'RAKP-HMAC-SHA1'
print("ULTIMATE TEST !!!! : " + test.ipmi_content_object.calc_hmac_kuid())
print("ULTIMATE TEST SIK !!!! : " + test.ipmi_content_object.calc_hmac_SIK())

sik = '173e96c8a67778f61854b78f67f823ebb66fceef'

test = IPMILanRequestMessage(ciphered_msg='32ab1c621a1964cce03f95399088bd99a928c28a5e1be42e246fa1d9cf90bdb9', ipmi_sik=sik, RCMP_auth_algorithm='RAKP-HMAC-SHA1')
print("REQ 1\n" + str(test))
test = IPMILanResponseMessage(ciphered_msg='3d8059a10de2edf1ff85e80e24acbfbdba4c317d42e67780d9675464e18b7003', ipmi_sik=sik, RCMP_auth_algorithm='RAKP-HMAC-SHA1')
print("RESP 1\n" + str(test))

test = IPMILanRequestMessage(ciphered_msg='85b643bcd2cefd646fc40bfca072cbdda94d4a0a8bc3b7b8fa3700b3fe39e189', ipmi_sik=sik, RCMP_auth_algorithm='RAKP-HMAC-SHA1')
print("REQ 2\n" + str(test))
test = IPMILanResponseMessage(ciphered_msg='3de76d03e8f556c425709f0c5bf706988821d9a889f3c2ef2fe1c42e1b5bbe04', ipmi_sik=sik, RCMP_auth_algorithm='RAKP-HMAC-SHA1')
print("RESP 2\n" + str(test))

test = IPMILanRequestMessage(ciphered_msg='9428168b5463f75b3cc45e7109eb6d9b3052241c794cd78c7de326e8e7ee708d', ipmi_sik=sik, RCMP_auth_algorithm='RAKP-HMAC-SHA1')
print("REQ 3\n" + str(test))
test = IPMILanResponseMessage(ciphered_msg='77603a8542277641ad5e4fd10b0f8e48b8089a4071f9f343cd8c7a33ad241961a8f2a96b46a76c273808863e43a2cf07', ipmi_sik=sik, RCMP_auth_algorithm='RAKP-HMAC-SHA1')
print("RESP 3\n" + str(test))

test = IPMILanRequestMessage(ciphered_msg='bfaf53b28017ef95d1a622efe48af7a05c6ac49d6e2e486a9eeb0ae1310dea39', ipmi_sik=sik, RCMP_auth_algorithm='RAKP-HMAC-SHA1')
print("REQ 4\n" + str(test))
test = IPMILanResponseMessage(ciphered_msg='f6fb4cdff0a2a3151243216d3a2706b28acd27ed5875f3c293d527af6d0ae816', ipmi_sik=sik, RCMP_auth_algorithm='RAKP-HMAC-SHA1')
print("RESP 4\n" + str(test))

test = IPMILanRequestMessage(ciphered_msg='ea0b4c8a36c9ea8bf9e9b04d7415c5a71c4d23d4c0ff62b82ab581dbc083300a', ipmi_sik=sik, RCMP_auth_algorithm='RAKP-HMAC-SHA1')
print("REQ 5\n" + str(test))
test = IPMILanResponseMessage(ciphered_msg='874037ca67ad0b140b5be5166a735f6046993248b7e42677396520f84e3e6799', ipmi_sik=sik, RCMP_auth_algorithm='RAKP-HMAC-SHA1')
print("RESP 5\n" + str(test))

test = IPMILanRequestMessage(ciphered_msg='c252871d8e72610a40a3ab2f2c0d6af204c173fafe63119b83d7c8c78f4fe524', ipmi_sik=sik, RCMP_auth_algorithm='RAKP-HMAC-SHA1')
print("REQ 6\n" + str(test))
test = IPMILanResponseMessage(ciphered_msg='6eab3f5e4de373602694cd60bcd31243d8d52a91908f1841347cfb6f5a7aba81', ipmi_sik=sik, RCMP_auth_algorithm='RAKP-HMAC-SHA1')
print("RESP 6\n" + str(test))

test = IPMILanRequestMessage(ciphered_msg='4d243d1e8b2910d3d98f8698cf605565d728541bf5cebd37488a45ca9d93b006', ipmi_sik=sik, RCMP_auth_algorithm='RAKP-HMAC-SHA1')
print("REQ 7\n" + str(test))
test = IPMILanResponseMessage(ciphered_msg='13490d7bf6198f02747518dee8773e5745eaddcc6421562b80543e916405d0cd', ipmi_sik=sik, RCMP_auth_algorithm='RAKP-HMAC-SHA1')
print("RESP 7\n" + str(test))

test = IPMIContentWrapper("RAKP Message 1", '000000007e78376b6ee4961322f58532337993b67203de41140000046d616173')
print(test.ipmi_content_object)

test = IPMIContentWrapper("RAKP Message 2", '00000000a4a3a2a0b5706129d087bd9de77971fabd8443ca7f6d88002ab511e58000001e67ec57caaf6e4b8fc9fac1864e115bd24157c55a5ed562d6')
print(test.ipmi_content_object)
test.ipmi_content_object.RAKP_message_1_managed_system_session_id = '7e78376b'
test.ipmi_content_object.RAKP_message_1_remote_console_random_number = '6ee4961322f58532337993b67203de41'
test.ipmi_content_object.RAKP_message_1_requested_max_privilege = '14'
test.ipmi_content_object.RAKP_message_1_user_name_length = '04'
test.ipmi_content_object.RAKP_message_1_user_name = '6d616173'
test.ipmi_content_object.associated_user_password = '3C7QT5FYzFVxL'
test.ipmi_content_object.RCMP_auth_algorithm = 'RAKP-HMAC-SHA1'
print("ULTIMATE TEST !!!! : " + test.ipmi_content_object.calc_hmac_kuid())
print("ULTIMATE TEST SIK !!!! : " + test.ipmi_content_object.calc_hmac_SIK())

sik = '854ac9a2d0880ce2d1234e1a4e069022570a6093'

test = IPMILanRequestMessage(ciphered_msg='12c3c6eb791032c6576c63cc5093a1dcc4ce2723d4cc34c5e0c50bc269ea337e', ipmi_sik=sik, RCMP_auth_algorithm='RAKP-HMAC-SHA1')
print("REQ 1\n" + str(test))
test = IPMILanResponseMessage(ciphered_msg='ff3ae38f3c57045435eccc7443eef2f9fd412f177e4fe7e4af54190272577b67', ipmi_sik=sik, RCMP_auth_algorithm='RAKP-HMAC-SHA1')
print("RESP 1\n" + str(test))

test = IPMILanRequestMessage(ciphered_msg='c4aacbd7687c3c13d72051893a9469bd657b536e4361b2fa5362e3d2dd204d88', ipmi_sik=sik, RCMP_auth_algorithm='RAKP-HMAC-SHA1')
print("REQ 2\n" + str(test))
test = IPMILanResponseMessage(ciphered_msg='5e53222edadfccc1593dbb16c1ffe0c150867b1ebb3224fea91a963a2108d294', ipmi_sik=sik, RCMP_auth_algorithm='RAKP-HMAC-SHA1')
print("RESP 2\n" + str(test))

test = IPMILanRequestMessage(ciphered_msg='06e235eda366ef5d5525f1f54dbab8d38ff3becd62c5c99d71ed0c0d7c9af476', ipmi_sik=sik, RCMP_auth_algorithm='RAKP-HMAC-SHA1')
print("REQ 3\n" + str(test))
test = IPMILanResponseMessage(ciphered_msg='39c450751b54c9514095c58484b77de295a05f9947f18220cfe458b14e12f9efac881ef626868d66feb70f68a7d36e42', ipmi_sik=sik, RCMP_auth_algorithm='RAKP-HMAC-SHA1')
print("RESP 3\n" + str(test))

test = IPMILanRequestMessage(ciphered_msg='b6525e582f59971bd3fb594e9d90430483204f83ffa3e8dff397884d74efe085', ipmi_sik=sik, RCMP_auth_algorithm='RAKP-HMAC-SHA1')
print("REQ 4\n" + str(test))
test = IPMILanResponseMessage(ciphered_msg='0a9f11e47edda5d71a61eddb60ce9c9911dd0a784076a9be3e189d76df080507', ipmi_sik=sik, RCMP_auth_algorithm='RAKP-HMAC-SHA1')
print("RESP 4\n" + str(test))

test = IPMILanRequestMessage(ciphered_msg='a0ecdeb81d0d04412d3f17067ef66ac9ebde36b71e6f3e489fbe166d91a5eb2e', ipmi_sik=sik, RCMP_auth_algorithm='RAKP-HMAC-SHA1')
print("REQ 5\n" + str(test))
test = IPMILanResponseMessage(ciphered_msg='92ec0ead40d7fe816dc305f17a82d3840ca222dcc6236d31dfcf68cc49e6de11', ipmi_sik=sik, RCMP_auth_algorithm='RAKP-HMAC-SHA1')
print("RESP 5\n" + str(test))

test = IPMILanRequestMessage(ciphered_msg='5b00a57894fe66270d294ebf2227a40b20c8906fb5c1243e65ea1f25591e0d8f', ipmi_sik=sik, RCMP_auth_algorithm='RAKP-HMAC-SHA1')
print("REQ 6\n" + str(test))
test = IPMILanResponseMessage(ciphered_msg='21e4689fc10e77db6f64b7cf325368c449abdc76275e7409e03249d62c745bb1', ipmi_sik=sik, RCMP_auth_algorithm='RAKP-HMAC-SHA1')
print("RESP 6\n" + str(test))

test = IPMILanRequestMessage(ciphered_msg='7e23c9db094d4043f7d58cb5c6e41fd3446818976a5dba386e07c9acc97ba938', ipmi_sik=sik, RCMP_auth_algorithm='RAKP-HMAC-SHA1')
print("REQ 7\n" + str(test))
test = IPMILanResponseMessage(ciphered_msg='407672804d7001ba3406abae887f33a9107456bebb9666a9b77a62cad5babaa6', ipmi_sik=sik, RCMP_auth_algorithm='RAKP-HMAC-SHA1')
print("RESP 7\n" + str(test))

test = IPMIContentWrapper("IPMI v1.5 payload", '2018c88100388e04b5')
print(test.ipmi_content_object)

test = IPMIContentWrapper("RMCP+ Open Session Response", '150003008a0a30d79a3dfeeb000000080100000801000008010000080200000801ff0207')
print(test.ipmi_content_object)

test = IPMIContentWrapper("RAKP Message 1", '000000009b52f94903d6d40a9522dbe083834aaac5d6ac1b140000046d616173')
print(test.ipmi_content_object)

#pass : 3C7QT5FYzFVxL
test = IPMIContentWrapper("RAKP Message 2", '00000000a4a3a2a047976ac92d5be34dd3ef1f6a7c88116a7f6d88002ab511e58000001e67ec57cad7526ec52928f1726f17f8f824cd518d635b78de')
print(test.ipmi_content_object)
test.ipmi_content_object.RAKP_message_1_managed_system_session_id = '9b52f949'
test.ipmi_content_object.RAKP_message_1_remote_console_random_number = '03d6d40a9522dbe083834aaac5d6ac1b'
test.ipmi_content_object.RAKP_message_1_requested_max_privilege = '14'
test.ipmi_content_object.RAKP_message_1_user_name_length = '04'
test.ipmi_content_object.RAKP_message_1_user_name = '6d616173'
test.ipmi_content_object.associated_user_password = '3C7QT5FYzFVxL'
test.ipmi_content_object.RCMP_auth_algorithm = 'RAKP-HMAC-SHA1'
print("ULTIMATE TEST !!!! : " + test.ipmi_content_object.calc_hmac_kuid())
print("ULTIMATE TEST SIK !!!! : " + test.ipmi_content_object.calc_hmac_SIK())
print(test.ipmi_content_object)

#6020a0dff35e4fac57160275793e067bc6981cf7
'''
test = IPMIContentWrapper("RMCP+ Open Session Request", '00000000a4a3a2a0000000080100000001000008010000000200000801000000')
print(test.ipmi_content_object)
test = IPMIContentWrapper("RMCP+ Open Session Response", '00000400a4a3a2a09b52f949000000080100000801000008010000080200000801ff0207')
print(test.ipmi_content_object)
from rmcp_message import RMCPMessage
from ipmi_session_wrapper import IPMISessionWrapper
from payload_ipmi_lan_req_msg import IPMILanRequest
from payload_ipmi_lan_resp_msg import IPMILanResponse
from payload_rmcp_open_session_req import PayloadRMCPOpenSessionRequest
from payload_rmcp_open_session_resp import PayloadRMCPOpenSessionResponse
from payload_RAKP_message_1 import PayloadRAKPMessage1
from payload_RAKP_message_2 import PayloadRAKPMessage2
from payload_RAKP_message_3 import PayloadRAKPMessage3
from payload_RAKP_message_4 import PayloadRAKPMessage4
from ipmi_2_0_no_trail import IPMI20NoTrailWrapper
from ipmi_2_0_trail import IPMI20TrailWrapper
from payload_ipmi_lan_ciphered_req_msg import IPMICipheredLanRequest
from payload_ipmi_lan_ciphered_resp_msg import IPMICipheredLanResponse
from ipmi_helper import IPMIHelper
from ipmi_content_wrapper import IPMIContentWrapper


a = IPMICipheredLanResponse(ciphered_msg = 'f18230f0380ea4d3a11a8def46368b8da7fd48b7f683f0d567b961d1b957b369',
                            ipmi_sik='b0027ce44cde097b2ce0bc4ae006a31e24455ae2',
                            RCMP_auth_algorithm='RAKP-HMAC-SHA1')
b = IPMICipheredLanResponse(ipmi_sik='b0027ce44cde097b2ce0bc4ae006a31e24455ae2',
    RCMP_auth_algorithm='RAKP-HMAC-SHA1',
    rqAddr=a.ipmi_lan_response_message.rqAddr,
    netFn=a.ipmi_lan_response_message.netFn,
    rqlun=a.ipmi_lan_response_message.rqLUN,
    rsAddr=a.ipmi_lan_response_message.rsAddr,
    rqSeq=a.ipmi_lan_response_message.rqSeq,
    rsLUN=a.ipmi_lan_response_message.rsLUN,
    command=a.ipmi_lan_response_message.command,
    completion_code='00',
    response_data=a.ipmi_lan_response_message.response_data)
print(a.serialize())
print(b.serialize())

response_ipmi_msg = IPMI20TrailWrapper(ipmi_auth_type='06',
                                        ipmi_payload_type=IPMIHelper.generate_rcmp_payload_type(is_payload_encrypted=True,
                                                                                                is_payload_authenticated=True, 
                                                                                                payload_type_definition="IPMI Message"),
                                        ipmi_session_seq='01000000',
                                        ipmi_session_id=IPMIHelper.invert_hex('a4a3a2a0'),
                                        message_content=a.serialize(),
                                        sik='b0027ce44cde097b2ce0bc4ae006a31e24455ae2',
                                        RCMP_auth_algorithm='RAKP-HMAC-SHA1')
                
print(response_ipmi_msg)
print(response_ipmi_msg.serialize())
#message received by the server
rcmp_msg_test = RMCPMessage(data = '0600ff0706c09b52f949030000002000f7a852ac1ddb8b3da989a7e4fbe7728c1f9903ebb5f8a1549b0f054a1f8c1761ffff0207996181f90f1daee9f77dc5a4')

#06c0a4a3a2a0010000002000f18230f0380ea4d3a11a8def46368b8da7fd48b7f683f0d567b961d1b957b369ffff0207b53a11515f651fcc6de1df35
#06c0a4a3a2a0010000002000f18230f0380ea4d3a11a8def46368b8da7fd48b7f683f0d567b961d1b957b369x207


rmcp_open_session_request = PayloadRMCPOpenSessionRequest(data = '00000000a4a3a2a0000000080100000001000008010000000200000801000000')
ipmi_rakp1_msg_content = PayloadRAKPMessage1(data='000000009b52f94903d6d40a9522dbe083834aaac5d6ac1b140000046d616173')
response_rakp2_msg_content = PayloadRAKPMessage2(data='00000000a4a3a2a047976ac92d5be34dd3ef1f6a7c88116a7f6d88002ab511e58000001e67ec57cad7526ec52928f1726f17f8f824cd518d635b78de')
response_rakp2_msg_content.RAKP_message_1_managed_system_session_id = ipmi_rakp1_msg_content.managed_system_session_id
response_rakp2_msg_content.RAKP_message_1_remote_console_random_number = ipmi_rakp1_msg_content.remote_console_random_number
response_rakp2_msg_content.RAKP_message_1_requested_max_privilege = ipmi_rakp1_msg_content.requested_max_privilege
response_rakp2_msg_content.RAKP_message_1_user_name_length = ipmi_rakp1_msg_content.user_name_length
response_rakp2_msg_content.RAKP_message_1_user_name = ipmi_rakp1_msg_content.user_name
response_rakp2_msg_content.associated_user_password = '3C7QT5FYzFVxL'
response_rakp2_msg_content.RCMP_auth_algorithm = IPMIHelper.get_auth_algorithm_definition(rmcp_open_session_request.get_auth_payload_auth_algo())

if rcmp_msg_test.rcmp_message_type == '07': #IPMI
    ipmi_msg = IPMISessionWrapper.get_IPMI_message_instance(rcmp_msg_test.rcmp_message_content)

    #ipmi v1.5 first comm request
    if ipmi_msg.ipmi_wrapper_type == "IPMI v1.5":
        ipmi_msg_content = IPMILanRequest(data = ipmi_msg.message_content)

        response_ipmi_msg_content = IPMILanResponse(
            rqAddr=ipmi_msg_content.rqAddr,
            netFn= IPMIHelper.increment_netFn(ipmi_msg_content.netFn),
            rqLUN=ipmi_msg_content.rqLUN,
            rsAddr=ipmi_msg_content.rsAddr,
            rqSeq=ipmi_msg_content.rqSeq,
            rsLUN=ipmi_msg_content.rsLUN,
            command=ipmi_msg_content.command,
            completion_code='00',#IPMIHelper.get_command_completion_code("OK"),
            response_data='0184040300000000')

        
        print(ipmi_msg_content)
        print(response_ipmi_msg_content)
        print(response_ipmi_msg_content.serialize())

    if ipmi_msg.ipmi_wrapper_type == "IPMI v2.0 NoTrail":
            #ipmi open session request
            if IPMIHelper.get_payload_type(ipmi_msg.ipmi_payload_type) == "RMCP+ Open Session Request":
                ipmi_msg_content = PayloadRMCPOpenSessionRequest(ipmi_msg.message_content)

                response_ipmi_msg_content = PayloadRMCPOpenSessionResponse( message_tag=ipmi_msg_content.message_tag, 
                                                                            rmcp_status_code=IPMIHelper.get_rcmp_status_code_value('No errors'), 
                                                                            max_privilege_level=IPMIHelper.get_requested_max_privilege_level_code('ADMINISTRATOR level'), 
                                                                            remote_console_session_id=ipmi_msg_content.remote_console_session_id, 
                                                                            auth_payload=ipmi_msg_content.auth_payload, 
                                                                            integrity_payload=ipmi_msg_content.integrity_payload, 
                                                                            confidentiality_payload=ipmi_msg_content.confidentiality_payload)
                
                response_ipmi_msg = IPMI20NoTrailWrapper(ipmi_auth_type=ipmi_msg.ipmi_auth_type,
                                                            ipmi_payload_type=IPMIHelper.generate_rcmp_payload_type(is_payload_encrypted=False,
                                                                                                                    is_payload_authenticated=False, 
                                                                                                                    payload_type_definition="RMCP+ Open Session Response"), 
                                                            ipmi_session_seq=ipmi_msg.ipmi_session_seq, 
                                                            ipmi_session_id=ipmi_msg.ipmi_session_id, 
                                                            message_content=response_ipmi_msg_content.serialize())
                #print(ipmi_msg)
                #print(ipmi_msg_content)
                #print(response_ipmi_msg_content)
                #print(response_ipmi_msg_content.serialize())
                print(response_ipmi_msg.serialize())
            #ipmi open session request
            if IPMIHelper.get_payload_type(ipmi_msg.ipmi_payload_type) == "RAKP Message 1":
                ipmi_rakp1_msg_content = PayloadRAKPMessage1(data=ipmi_msg.message_content)

                response_rakp2_msg_content = PayloadRAKPMessage2(RAKP_message_1_message_tag=ipmi_rakp1_msg_content.message_tag,
                                                                    rcmp_status_code=IPMIHelper.get_rcmp_status_code_value('No errors'),
                                                                    RCMP_remote_console_session_id=rmcp_open_session_request.remote_console_session_id,
                                                                    RAKP_message_1_managed_system_session_id=ipmi_rakp1_msg_content.managed_system_session_id,
                                                                    RAKP_message_1_remote_console_random_number=ipmi_rakp1_msg_content.remote_console_random_number,
                                                                    RAKP_message_1_requested_max_privilege=ipmi_rakp1_msg_content.requested_max_privilege,
                                                                    RAKP_message_1_user_name_length=ipmi_rakp1_msg_content.user_name_length,
                                                                    RAKP_message_1_user_name=ipmi_rakp1_msg_content.user_name,
                                                                    associated_user_password='3C7QT5FYzFVxL',
                                                                    RCMP_auth_algorithm=IPMIHelper.get_auth_algorithm_definition(rmcp_open_session_request.get_auth_payload_auth_algo()))

                print(response_rakp2_msg_content)
                print(response_rakp2_msg_content.serialize())
            
            if IPMIHelper.get_payload_type(ipmi_msg.ipmi_payload_type) == "RAKP Message 3":
                ipmi_rakp3_msg_content = PayloadRAKPMessage1(data=ipmi_msg.message_content)

                response_rakp4_msg_content = PayloadRAKPMessage4(RAKP_message_3_message_tag=ipmi_rakp3_msg_content.message_tag,
                                                                    rcmp_status_code=IPMIHelper.get_rcmp_status_code_value('No errors'),
                                                                    RCMP_remote_console_session_id=rmcp_open_session_request.remote_console_session_id,
                                                                    SIK=response_rakp2_msg_content.SIK,
                                                                    RCMP_auth_algorithm=IPMIHelper.get_auth_algorithm_definition(rmcp_open_session_request.get_auth_payload_auth_algo()),
                                                                    RAKP_message_1_remote_console_random_number=ipmi_rakp1_msg_content.remote_console_random_number,
                                                                    RAKP_message_1_managed_system_session_id=ipmi_rakp1_msg_content.managed_system_session_id, 
                                                                    RAKP_message_2_managed_system_GUID=response_rakp2_msg_content.managed_system_GUID)

                print(response_rakp4_msg_content)
                print(response_rakp4_msg_content.serialize())

    if ipmi_msg.ipmi_wrapper_type == "IPMI v2.0 Trail":
        ipmi_ciphered_msg_request = IPMICipheredLanRequest(ciphered_msg = ipmi_msg.message_content, ipmi_sik=response_rakp2_msg_content.calc_hmac_SIK(), RCMP_auth_algorithm=IPMIHelper.get_auth_algorithm_definition(rmcp_open_session_request.get_auth_payload_auth_algo()))

        if IPMIHelper.get_netFn_definition(ipmi_ciphered_msg_request.extract_netFn()) == "Reserved":

            ipmi_ciphered_msg_response = IPMICipheredLanResponse(ipmi_sik=response_rakp2_msg_content.calc_hmac_SIK(),
                                                                RCMP_auth_algorithm=IPMIHelper.get_auth_algorithm_definition(rmcp_open_session_request.get_auth_payload_auth_algo()),
                                                                rqAddr=ipmi_ciphered_msg_request.ipmi_lan_request_message.rqAddr,
                                                                netFn=ipmi_ciphered_msg_request.ipmi_lan_request_message.netFn,
                                                                rqlun=ipmi_ciphered_msg_request.ipmi_lan_request_message.rqLUN,
                                                                rsAddr=ipmi_ciphered_msg_request.ipmi_lan_request_message.rsAddr,
                                                                rqSeq=ipmi_ciphered_msg_request.ipmi_lan_request_message.rqSeq,
                                                                rsLUN=ipmi_ciphered_msg_request.ipmi_lan_request_message.rsLUN,
                                                                command=ipmi_ciphered_msg_request.ipmi_lan_request_message.command,
                                                                completion_code='c1',
                                                                response_data='')

            print(ipmi_ciphered_msg_response)

        elif IPMIHelper.get_netFn_definition(ipmi_ciphered_msg_request.extract_netFn()) == "App" and ipmi_ciphered_msg_request.ipmi_lan_request_message.command == "3b":

            ipmi_ciphered_msg_response = IPMICipheredLanResponse(ipmi_sik=response_rakp2_msg_content.calc_hmac_SIK(),
                                                                RCMP_auth_algorithm=IPMIHelper.get_auth_algorithm_definition(rmcp_open_session_request.get_auth_payload_auth_algo()),
                                                                rqAddr=ipmi_ciphered_msg_request.ipmi_lan_request_message.rqAddr,
                                                                netFn=ipmi_ciphered_msg_request.ipmi_lan_request_message.netFn,
                                                                rqlun=ipmi_ciphered_msg_request.ipmi_lan_request_message.rqLUN,
                                                                rsAddr=ipmi_ciphered_msg_request.ipmi_lan_request_message.rsAddr,
                                                                rqSeq=ipmi_ciphered_msg_request.ipmi_lan_request_message.rqSeq,
                                                                rsLUN=ipmi_ciphered_msg_request.ipmi_lan_request_message.rsLUN,
                                                                command=ipmi_ciphered_msg_request.ipmi_lan_request_message.command,
                                                                completion_code='00',
                                                                response_data=ipmi_ciphered_msg_request.ipmi_lan_request_message.request_data)

            print(ipmi_ciphered_msg_response)

        elif IPMIHelper.get_netFn_definition(ipmi_ciphered_msg_request.extract_netFn()) == "App" and ipmi_ciphered_msg_request.ipmi_lan_request_message.command == "01":

            ipmi_ciphered_msg_response = IPMICipheredLanResponse(ipmi_sik=response_rakp2_msg_content.calc_hmac_SIK(),
                                                                RCMP_auth_algorithm=IPMIHelper.get_auth_algorithm_definition(rmcp_open_session_request.get_auth_payload_auth_algo()),
                                                                rqAddr=ipmi_ciphered_msg_request.ipmi_lan_request_message.rqAddr,
                                                                netFn=ipmi_ciphered_msg_request.ipmi_lan_request_message.netFn,
                                                                rqlun=ipmi_ciphered_msg_request.ipmi_lan_request_message.rqLUN,
                                                                rsAddr=ipmi_ciphered_msg_request.ipmi_lan_request_message.rsAddr,
                                                                rqSeq=ipmi_ciphered_msg_request.ipmi_lan_request_message.rqSeq,
                                                                rsLUN=ipmi_ciphered_msg_request.ipmi_lan_request_message.rsLUN,
                                                                command=ipmi_ciphered_msg_request.ipmi_lan_request_message.command,
                                                                completion_code='00',
                                                                response_data='7656543655765276')

            print(ipmi_ciphered_msg_response)

        elif IPMIHelper.get_netFn_definition(ipmi_ciphered_msg_request.extract_netFn()) == "Chassis" and ipmi_ciphered_msg_request.ipmi_lan_request_message.command == "01":

            ipmi_ciphered_msg_response = IPMICipheredLanResponse(ipmi_sik=response_rakp2_msg_content.calc_hmac_SIK(),
                                                                RCMP_auth_algorithm=IPMIHelper.get_auth_algorithm_definition(rmcp_open_session_request.get_auth_payload_auth_algo()),
                                                                rqAddr=ipmi_ciphered_msg_request.ipmi_lan_request_message.rqAddr,
                                                                netFn=ipmi_ciphered_msg_request.ipmi_lan_request_message.netFn,
                                                                rqlun=ipmi_ciphered_msg_request.ipmi_lan_request_message.rqLUN,
                                                                rsAddr=ipmi_ciphered_msg_request.ipmi_lan_request_message.rsAddr,
                                                                rqSeq=ipmi_ciphered_msg_request.ipmi_lan_request_message.rqSeq,
                                                                rsLUN=ipmi_ciphered_msg_request.ipmi_lan_request_message.rsLUN,
                                                                command=ipmi_ciphered_msg_request.ipmi_lan_request_message.command,
                                                                completion_code='00',
                                                                response_data='40004070')

            print(ipmi_ciphered_msg_response)

        elif IPMIHelper.get_netFn_definition(ipmi_ciphered_msg_request.extract_netFn()) == "App" and ipmi_ciphered_msg_request.ipmi_lan_request_message.command == "3c":

            ipmi_ciphered_msg_response = IPMICipheredLanResponse(ipmi_sik=response_rakp2_msg_content.calc_hmac_SIK(),
                                                                RCMP_auth_algorithm=IPMIHelper.get_auth_algorithm_definition(rmcp_open_session_request.get_auth_payload_auth_algo()),
                                                                rqAddr=ipmi_ciphered_msg_request.ipmi_lan_request_message.rqAddr,
                                                                netFn=ipmi_ciphered_msg_request.ipmi_lan_request_message.netFn,
                                                                rqlun=ipmi_ciphered_msg_request.ipmi_lan_request_message.rqLUN,
                                                                rsAddr=ipmi_ciphered_msg_request.ipmi_lan_request_message.rsAddr,
                                                                rqSeq=ipmi_ciphered_msg_request.ipmi_lan_request_message.rqSeq,
                                                                rsLUN=ipmi_ciphered_msg_request.ipmi_lan_request_message.rsLUN,
                                                                command=ipmi_ciphered_msg_request.ipmi_lan_request_message.command,
                                                                completion_code='00',
                                                                response_data=IPMIHelper.invert_hex(rmcp_open_session_request.remote_console_session_id))

            print(ipmi_ciphered_msg_response)

            self.ipmi_wrapper_type = "IPMI v2.0 Trail"
            self.ipmi_auth_type = keys['ipmi_auth_type']
            self.ipmi_payload_encrypted = keys['ipmi_payload_encrypted']
            self.ipmi_payload_authentication = keys['ipmi_payload_authentication']
            self.ipmi_payload_type = keys['ipmi_payload_type']
            self.ipmi_session_seq = keys['ipmi_session_seq']
            self.ipmi_session_id = keys['ipmi_session_id']
            self.message_content = keys['message_content']
            '''
            response_ipmi_ms = IPMI20TrailWrapper(ipmi_auth_type=ipmi_msg.ipmi_auth_type,
                                                    ipmi_payload_type=IPMIHelper.generate_rcmp_payload_type(is_payload_encrypted=True,
                                                                                                            is_payload_authenticated=True, 
                                                                                                            payload_type_definition="IPMI Message"),
                                                    ipmi_session_seq=,
                                                    ipmi_session_id=,
                                                    message_content=)
        
            '''



        print(ipmi_ciphered_msg_request)




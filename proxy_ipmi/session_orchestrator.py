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
from ipmi_1_5_no_auth import IPMI15SessionWrapper
from payload_ipmi_lan_ciphered_req_msg import IPMICipheredLanRequest
from payload_ipmi_lan_ciphered_resp_msg import IPMICipheredLanResponse
from ipmi_helper import IPMIHelper
from ipmi_session import IPMISession
from ipmi_lan_enveloppe import IPMILanEnveloppe
import time

class SessionOrchestrator():

    def __init__(self):
        self.session = None

    def addSession(self, session):
        self.session = session

    def treat_message(self, message_in, sender_ip_port):

        rmcp_message = RMCPMessage(data = message_in)
        data_dict = {}

        if rmcp_message.rcmp_message_type == '07': #IPMI
            ipmi_msg = IPMISessionWrapper.get_IPMI_message_instance(rmcp_message.rcmp_message_content)
            #data_dict['wrapper_type'] = ipmi_msg.ipmi_wrapper_type
            #data_dict['data'] = ipmi_msg.ipmi_wrapper_type

            if ipmi_msg.ipmi_wrapper_type == "IPMI v1.5":

                ipmi_message = IPMILanEnveloppe(wrapper_type=ipmi_msg.ipmi_wrapper_type, data=ipmi_msg.message_content)

                #ipmi v1.5 dumb management (no session, only respond to requests or responses)
                if ipmi_msg.ipmi_wrapper_type == "IPMI v1.5" and ipmi_message.message_type == "Request":
                    '''
                    data_dict['rqAddr'] = ipmi_message.ipmi_lan_message.rqAddr
                    data_dict['netFn'] = ipmi_message.ipmi_lan_message.netFn
                    data_dict['rqLUN'] = ipmi_message.ipmi_lan_message.rqLUN
                    data_dict['rsAddr'] = ipmi_message.ipmi_lan_message.rsAddr
                    data_dict['rqSeq'] = ipmi_message.ipmi_lan_message.rqSeq
                    data_dict['rsLUN'] = ipmi_message.ipmi_lan_message.rsLUN
                    data_dict['command'] = ipmi_message.ipmi_lan_message.command
                    data_dict['completion_code'] = '00'
                    data_dict['response_data'] = '0184040300000000'
                    '''

                    print('\nReceived IPMI15 Request from ' + str(sender_ip_port) + ' : \n' + str(ipmi_message))

                    response_ipmi_msg_content = IPMILanEnveloppe(rqAddr=ipmi_message.ipmi_lan_message.rqAddr,
                                                                    netFn=ipmi_message.ipmi_lan_message.netFn,
                                                                    rqLUN=ipmi_message.ipmi_lan_message.rqLUN,
                                                                    rsAddr=ipmi_message.ipmi_lan_message.rsAddr,
                                                                    rqSeq=ipmi_message.ipmi_lan_message.rqSeq,
                                                                    rsLUN=ipmi_message.ipmi_lan_message.rsLUN,
                                                                    command=ipmi_message.ipmi_lan_message.command,
                                                                    completion_code='00',
                                                                    response_data='0184040300000000')
                    
                    response_ipmi = IPMI15SessionWrapper(ipmi_auth_type=IPMIHelper.get_auth_code(ipmi_msg.ipmi_auth_type),
                                                        ipmi_session_seq=ipmi_msg.ipmi_session_seq,
                                                        ipmi_session_id=ipmi_msg.ipmi_session_id,
                                                        message_length=IPMIHelper.calculate_message_length(response_ipmi_msg_content.serialize()),
                                                        message_content=response_ipmi_msg_content.serialize())

                    response_rcmp = RMCPMessage(rcmp_version=rmcp_message.rcmp_version,
                                                rcmp_reserved=rmcp_message.rcmp_reserved,
                                                rcmp_sequence=rmcp_message.rcmp_sequence,
                                                rcmp_message_type=rmcp_message.rcmp_message_type,
                                                rcmp_message_content=response_ipmi.serialize())

                    #print(response_ipmi_msg_content)
                    #print(response_ipmi_msg_content)
                    #print(response_ipmi_msg_content.serialize())
                    #print(response_ipmi)
                    print('\nForged IPMI15 Response for ' + str(sender_ip_port) + ' : \n' + str(response_ipmi_msg_content))

                    return [[sender_ip_port, response_rcmp.serialize()]]

                if ipmi_msg.ipmi_wrapper_type == "IPMI v1.5" and ipmi_message.message_type == "Response":
                    '''
                    open_session_data = {}
                    open_session_data['message_tag'] = '00'
                    open_session_data['requested_max_privilege'] = '00'
                    open_session_data['remote_console_session_id'] = self.session.get_remote_console_session_id
                    open_session_data['auth_payload'] = '0000000801000000'
                    open_session_data['integrity_payload'] = '0100000801000000'
                    open_session_data['confidentiality_payload'] = '0200000801000000'
                    '''

                    print('\nReceived IPMI15 Response from ' + str(sender_ip_port) + ' : \n' + str(ipmi_message))

                    open_session_msg_content = PayloadRMCPOpenSessionRequest(message_tag='00',
                                                                                requested_max_privilege='00',
                                                                                remote_console_session_id=self.session.session_id,
                                                                                auth_payload='0000000801000000',
                                                                                integrity_payload='0100000801000000',
                                                                                confidentiality_payload='0200000801000000')

                    

                    response_ipmi = IPMI20NoTrailWrapper(ipmi_auth_type='06',
                                                            ipmi_payload_type=IPMIHelper.generate_rcmp_payload_type(is_payload_encrypted=False,
                                                                                                                    is_payload_authenticated=False, 
                                                                                                                    payload_type_definition="RMCP+ Open Session Request"), 
                                                            ipmi_session_seq='00000000', 
                                                            ipmi_session_id='00000000', 
                                                            message_content=open_session_msg_content.serialize())

                    response_rcmp = RMCPMessage(rcmp_version=rmcp_message.rcmp_version,
                                                rcmp_reserved=rmcp_message.rcmp_reserved,
                                                rcmp_sequence=rmcp_message.rcmp_sequence,
                                                rcmp_message_type=rmcp_message.rcmp_message_type,
                                                rcmp_message_content=response_ipmi.serialize())         
                    
                    print('\nForged RMCPOpenSessionRequest for ' + str(sender_ip_port) + ' : \n' + str(open_session_msg_content))
                    #print('Response : \n' + str(open_session_msg_content))

                    return [[sender_ip_port, response_rcmp.serialize()]]

            if ipmi_msg.ipmi_wrapper_type == "IPMI v2.0 NoTrail":
                #ipmi open session request
                if IPMIHelper.get_payload_type(ipmi_msg.ipmi_payload_type) == "RMCP+ Open Session Request":
                    ipmi_msg_content = PayloadRMCPOpenSessionRequest(data=ipmi_msg.message_content)

                    print('\nReceived Open Session Request from ' + str(sender_ip_port) + ' : \n' + str(ipmi_msg_content))

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

                    response_rcmp = RMCPMessage(rcmp_version=rmcp_message.rcmp_version,
                                            rcmp_reserved=rmcp_message.rcmp_reserved,
                                            rcmp_sequence=rmcp_message.rcmp_sequence,
                                            rcmp_message_type=rmcp_message.rcmp_message_type,
                                            rcmp_message_content=response_ipmi_msg.serialize())
                    
                    self.addSession(IPMISession(response_ipmi_msg_content.managed_system_session_id))
                    self.session.remote_console_session_id = response_ipmi_msg_content.remote_console_session_id
                    self.session.console_ip = sender_ip_port[0]
                    self.session.password = 'password'
                    self.session.auth_algorithm = response_ipmi_msg_content.get_auth_payload_auth_algo()
                    print("\nSession  created ! \n" + self.session.session_id)
                    #print(response_ipmi_msg.serialize())

                    #print('Response : \n' + str(response_ipmi_msg_content))

                    print('\nForged RMCPOpenSession Response for ' + str(sender_ip_port) + ' : \n' + str(response_ipmi_msg_content))
                    return [[sender_ip_port, response_rcmp.serialize()]]

                if IPMIHelper.get_payload_type(ipmi_msg.ipmi_payload_type) == "RMCP+ Open Session Response":
                    ipmi_msg_content = PayloadRMCPOpenSessionResponse(data=ipmi_msg.message_content)

                    print('\nReceived Open Session Response from ' + str(sender_ip_port) + ' : \n' + str(ipmi_msg_content))

                    self.session.server_managed_system_session_id = ipmi_msg_content.managed_system_session_id

                    response_rakp1_msg_content = PayloadRAKPMessage1(rcmp_open_session_response_managed_system_session_id=self.session.server_managed_system_session_id,
                                                                        requested_max_privilege=IPMIHelper.get_requested_max_privilege_level_code('ADMINISTRATOR level'),
                                                                        user_name_length=IPMIHelper.calculate_string_length_1_byte_hex(self.session.server_username),
                                                                        user_name=IPMIHelper.get_username_hex(self.session.server_username))

                    self.session.server_RAKP_message_1_remote_console_random_number = response_rakp1_msg_content.remote_console_random_number
                    self.session.server_request_max_privilege = response_rakp1_msg_content.requested_max_privilege

                    response_ipmi_msg = IPMI20NoTrailWrapper(ipmi_auth_type=ipmi_msg.ipmi_auth_type,
                                                                ipmi_payload_type=IPMIHelper.generate_rcmp_payload_type(is_payload_encrypted=False,
                                                                                                                        is_payload_authenticated=False, 
                                                                                                                        payload_type_definition="RAKP Message 1"), 
                                                                ipmi_session_seq=ipmi_msg.ipmi_session_seq, 
                                                                ipmi_session_id=ipmi_msg.ipmi_session_id, 
                                                                message_content=response_rakp1_msg_content.serialize())

                    response_rcmp = RMCPMessage(rcmp_version=rmcp_message.rcmp_version,
                                            rcmp_reserved=rmcp_message.rcmp_reserved,
                                            rcmp_sequence=rmcp_message.rcmp_sequence,
                                            rcmp_message_type=rmcp_message.rcmp_message_type,
                                            rcmp_message_content=response_ipmi_msg.serialize())
                    
                    #print('Response : \n' + str(response_rakp1_msg_content))
                    print('\nForged PayloadRAKPMessage1 for ' + str(sender_ip_port) + ' : \n' + str(response_rakp1_msg_content))
                    return [[sender_ip_port, response_rcmp.serialize()]]

                #ipmi auth
                if IPMIHelper.get_payload_type(ipmi_msg.ipmi_payload_type) == "RAKP Message 1":
                    ipmi_rakp1_msg_content = PayloadRAKPMessage1(data=ipmi_msg.message_content)

                    print('\nReceived RAKP Message 1 from ' + str(sender_ip_port) + ' : \n' + str(ipmi_rakp1_msg_content))

                    response_rakp2_msg_content = PayloadRAKPMessage2(RAKP_message_1_message_tag=ipmi_rakp1_msg_content.message_tag,
                                                                        rcmp_status_code=IPMIHelper.get_rcmp_status_code_value('No errors'),
                                                                        RCMP_remote_console_session_id=self.session.remote_console_session_id,
                                                                        RAKP_message_1_managed_system_session_id=ipmi_rakp1_msg_content.managed_system_session_id,
                                                                        RAKP_message_1_remote_console_random_number=ipmi_rakp1_msg_content.remote_console_random_number,
                                                                        RAKP_message_1_requested_max_privilege=ipmi_rakp1_msg_content.requested_max_privilege,
                                                                        RAKP_message_1_user_name_length=ipmi_rakp1_msg_content.user_name_length,
                                                                        RAKP_message_1_user_name=ipmi_rakp1_msg_content.user_name,
                                                                        associated_user_password=self.session.password,
                                                                        RCMP_auth_algorithm=IPMIHelper.get_auth_algorithm_definition(self.session.auth_algorithm))

                    #print(response_rakp2_msg_content)
                    #print(response_rakp2_msg_content.serialize())

                    response_ipmi_msg = IPMI20NoTrailWrapper(ipmi_auth_type=ipmi_msg.ipmi_auth_type,
                                                                ipmi_payload_type=IPMIHelper.generate_rcmp_payload_type(is_payload_encrypted=False,
                                                                                                                        is_payload_authenticated=False, 
                                                                                                                        payload_type_definition="RAKP Message 2"), 
                                                                ipmi_session_seq=ipmi_msg.ipmi_session_seq, 
                                                                ipmi_session_id=ipmi_msg.ipmi_session_id, 
                                                                message_content=response_rakp2_msg_content.serialize())

                    response_rcmp = RMCPMessage(rcmp_version=rmcp_message.rcmp_version,
                                            rcmp_reserved=rmcp_message.rcmp_reserved,
                                            rcmp_sequence=rmcp_message.rcmp_sequence,
                                            rcmp_message_type=rmcp_message.rcmp_message_type,
                                            rcmp_message_content=response_ipmi_msg.serialize())

                    self.session.SIK = response_rakp2_msg_content.SIK
                    self.session.remote_console_random_number = ipmi_rakp1_msg_content.remote_console_random_number
                    self.session.RAKP_message_2_managed_system_GUID = response_rakp2_msg_content.managed_system_GUID
                    self.session.server_request_max_privilege = response_rakp2_msg_content.RAKP_message_1_requested_max_privilege
                    self.session.server_ip = "178.32.242.0"
                    self.session.server_password = "3C7QT5FYzFVxL"
                    self.session.server_username = 'maas'

                    request_ipmi_msg_content = IPMILanEnveloppe(rsAddr='20',
                                                                    netFn='011000',
                                                                    rsLUN='00',
                                                                    rqAddr='81',
                                                                    rqSeq='000000',
                                                                    rqLUN='00',
                                                                    command='38',
                                                                    request_data='8e04')
                    
                    request_ipmi = IPMI15SessionWrapper(ipmi_auth_type='00',
                                                        ipmi_session_seq='00000000',
                                                        ipmi_session_id='00000000',
                                                        message_length='09',
                                                        message_content=request_ipmi_msg_content.serialize())

                    request_rcmp = RMCPMessage(rcmp_version=rmcp_message.rcmp_version,
                                                rcmp_reserved=rmcp_message.rcmp_reserved,
                                                rcmp_sequence=rmcp_message.rcmp_sequence,
                                                rcmp_message_type=rmcp_message.rcmp_message_type,
                                                rcmp_message_content=request_ipmi.serialize())


                    print('\nForged PayloadRAKPMessage2 for ' + str(sender_ip_port) + ' : \n' + str(response_rakp2_msg_content))
                    print('\nForged IPMILanEnveloppe for ' + str((self.session.server_ip, 623)) + ' : \n' + str(request_ipmi_msg_content))

                    return [[(self.session.server_ip, 623), request_rcmp.serialize()], [sender_ip_port, response_rcmp.serialize()]]

                if IPMIHelper.get_payload_type(ipmi_msg.ipmi_payload_type) == "RAKP Message 2":

                    ipmi_rakp2_msg_content = PayloadRAKPMessage2(data=ipmi_msg.message_content,
                                                                    RAKP_message_1_requested_max_privilege=self.session.server_request_max_privilege,
                                                                    RAKP_message_1_remote_console_random_number=self.session.server_RAKP_message_1_remote_console_random_number,
                                                                    RAKP_message_1_user_name_length=IPMIHelper.calculate_string_length_1_byte_hex(self.session.server_username),
                                                                    RAKP_message_1_user_name=IPMIHelper.get_username_hex(self.session.server_username),
                                                                    associated_user_password=IPMIHelper.get_username_hex(self.session.server_password),
                                                                    RCMP_auth_algorithm=IPMIHelper.get_auth_algorithm_definition(self.session.auth_algorithm))

                    print('\nReceived RAKP Message 2 from ' + str(sender_ip_port) + ' : \n' + str(ipmi_rakp2_msg_content))

                    self.session.server_SIK = ipmi_rakp2_msg_content.SIK
                    self.session.server_RAKP_message_2_managed_system_GUID = ipmi_rakp2_msg_content.managed_system_GUID

                    response_rakp3_msg_content = PayloadRAKPMessage3(message_tag=ipmi_rakp2_msg_content.RAKP_message_1_message_tag,
                                                                        rcmp_status_code=IPMIHelper.get_rcmp_status_code_value('No errors'),
                                                                        managed_system_session_id=self.session.server_managed_system_session_id,
                                                                        RCMP_auth_algorithm=IPMIHelper.get_auth_algorithm_definition(self.session.auth_algorithm),
                                                                        RAKP_message_2_managed_system_random_number=ipmi_rakp2_msg_content.managed_system_random_number,
                                                                        RCMP_remote_console_session_id=ipmi_rakp2_msg_content.RCMP_remote_console_session_id,
                                                                        RAKP_message_1_requested_max_privilege=self.session.server_request_max_privilege,
                                                                        RAKP_message_1_user_name_length=IPMIHelper.calculate_string_length_1_byte_hex(self.session.server_username),
                                                                        RAKP_message_1_user_name=IPMIHelper.get_username_hex(self.session.server_username),
                                                                        associated_user_password=self.session.server_password)

                    #print(response_rakp3_msg_content)
                    #print(response_rakp3_msg_content.serialize())

                    response_ipmi_msg = IPMI20NoTrailWrapper(ipmi_auth_type=ipmi_msg.ipmi_auth_type,
                                                                ipmi_payload_type=IPMIHelper.generate_rcmp_payload_type(is_payload_encrypted=False,
                                                                                                                        is_payload_authenticated=False, 
                                                                                                                        payload_type_definition="RAKP Message 3"), 
                                                                ipmi_session_seq=ipmi_msg.ipmi_session_seq, 
                                                                ipmi_session_id=ipmi_msg.ipmi_session_id, 
                                                                message_content=response_rakp3_msg_content.serialize())

                    response_rcmp = RMCPMessage(rcmp_version=rmcp_message.rcmp_version,
                                            rcmp_reserved=rmcp_message.rcmp_reserved,
                                            rcmp_sequence=rmcp_message.rcmp_sequence,
                                            rcmp_message_type=rmcp_message.rcmp_message_type,
                                            rcmp_message_content=response_ipmi_msg.serialize())

                
                    print('\nForged PayloadRAKPMessage3 for ' + str(sender_ip_port) + ' : \n' + str(response_rakp3_msg_content))

                    return [[sender_ip_port, response_rcmp.serialize()]]
                
                if IPMIHelper.get_payload_type(ipmi_msg.ipmi_payload_type) == "RAKP Message 3":
                    ipmi_rakp3_msg_content = PayloadRAKPMessage3(data=ipmi_msg.message_content)

                    print('\nReceived RAKP Message 3 from ' + str(sender_ip_port) + ' : \n' + str(ipmi_rakp3_msg_content))

                    response_rakp4_msg_content = PayloadRAKPMessage4(RAKP_message_3_message_tag=ipmi_rakp3_msg_content.message_tag,
                                                                        rcmp_status_code=IPMIHelper.get_rcmp_status_code_value('No errors'),
                                                                        RCMP_remote_console_session_id=self.session.remote_console_session_id,
                                                                        SIK=self.session.SIK,
                                                                        RCMP_auth_algorithm=IPMIHelper.get_auth_algorithm_definition(self.session.auth_algorithm),
                                                                        RAKP_message_1_remote_console_random_number=self.session.remote_console_random_number,
                                                                        RAKP_message_1_managed_system_session_id=self.session.session_id, 
                                                                        RAKP_message_2_managed_system_GUID=self.session.RAKP_message_2_managed_system_GUID)

                    #print(response_rakp4_msg_content)
                    #print(response_rakp4_msg_content.serialize())

                    response_ipmi_msg = IPMI20NoTrailWrapper(ipmi_auth_type=ipmi_msg.ipmi_auth_type,
                                                                ipmi_payload_type=IPMIHelper.generate_rcmp_payload_type(is_payload_encrypted=False,
                                                                                                                        is_payload_authenticated=False, 
                                                                                                                        payload_type_definition="RAKP Message 4"), 
                                                                ipmi_session_seq=ipmi_msg.ipmi_session_seq, 
                                                                ipmi_session_id=ipmi_msg.ipmi_session_id, 
                                                                message_content=response_rakp4_msg_content.serialize())

                    response_rcmp = RMCPMessage(rcmp_version=rmcp_message.rcmp_version,
                                            rcmp_reserved=rmcp_message.rcmp_reserved,
                                            rcmp_sequence=rmcp_message.rcmp_sequence,
                                            rcmp_message_type=rmcp_message.rcmp_message_type,
                                            rcmp_message_content=response_ipmi_msg.serialize())

                    print('\nForged PayloadRAKPMessage4 for ' + str(sender_ip_port) + ' : \n' + str(response_rakp4_msg_content))

                    return [[sender_ip_port, response_rcmp.serialize()]]

                if IPMIHelper.get_payload_type(ipmi_msg.ipmi_payload_type) == "RAKP Message 4":
                    ipmi_rakp4_msg_content = PayloadRAKPMessage4(data=ipmi_msg.message_content)

                    print('\nReceived RAKP Message 4 from ' + str(sender_ip_port) + ' : \n' + str(ipmi_rakp4_msg_content))

                    while not self.session.console_message:
                        time.sleep(0.1)

                    ipmi_request_msg_content = IPMILanEnveloppe(ipmi_sik=self.session.server_SIK,
                                                                RCMP_auth_algorithm=IPMIHelper.get_auth_algorithm_definition(self.session.auth_algorithm),
                                                                rsAddr=self.session.console_message.rsAddr,
                                                                netFn=self.session.console_message.netFn,
                                                                rsLUN=self.session.console_message.rsLUN, 
                                                                rqAddr=self.session.console_message.rqAddr,
                                                                rqSeq=self.session.console_message.rqSeq,
                                                                rqLUN=self.session.console_message.rqLUN,
                                                                command=self.session.console_message.command,
                                                                request_data=self.session.console_message.request_data)

                    #print(ipmi_request_msg_content)
                    #print(ipmi_request_msg_content.serialize())

                    response_ipmi_msg = IPMI20TrailWrapper(ipmi_auth_type=ipmi_msg.ipmi_auth_type,
                                                            ipmi_payload_type=IPMIHelper.generate_rcmp_payload_type(is_payload_encrypted=True,
                                                                                                                    is_payload_authenticated=True, 
                                                                                                                    payload_type_definition="IPMI Message"),
                                                            ipmi_session_seq=self.session.session_sequence,
                                                            ipmi_session_id=IPMIHelper.invert_hex(self.session.server_managed_system_session_id),
                                                            message_content=ipmi_request_msg_content.serialize(),
                                                            sik=self.session.server_SIK,
                                                            RCMP_auth_algorithm=IPMIHelper.get_auth_algorithm_definition(self.session.auth_algorithm))

                    response_rcmp = RMCPMessage(rcmp_version=rmcp_message.rcmp_version,
                                            rcmp_reserved=rmcp_message.rcmp_reserved,
                                            rcmp_sequence=rmcp_message.rcmp_sequence,
                                            rcmp_message_type=rmcp_message.rcmp_message_type,
                                            rcmp_message_content=response_ipmi_msg.serialize())

                    print('\nForged IPMIMsg for ' + str(sender_ip_port) + ' : \n' + str(ipmi_request_msg_content))

                    self.session.console_message = None

                    if not response_rcmp.serialize():
                        raise AttributeError('empty')

                    return [[sender_ip_port, response_rcmp.serialize()]]

            if ipmi_msg.ipmi_wrapper_type == "IPMI v2.0 Trail":

                #ipmi_message = IPMILanEnveloppe(wrapper_type=ipmi_msg.ipmi_wrapper_type, ipmi_sik=self.session.SIK, RCMP_auth_algorithm=IPMIHelper.get_auth_algorithm_definition(self.session.auth_algorithm), ciphered_msg=ipmi_msg.message_content)

                
                if sender_ip_port[0] == self.session.server_ip:
                    ipmi_ciphered_msg = IPMILanEnveloppe(wrapper_type = ipmi_msg.ipmi_wrapper_type, 
                                                                    ciphered_msg=ipmi_msg.message_content, 
                                                                    ipmi_sik=self.session.server_SIK , 
                                                                    RCMP_auth_algorithm=IPMIHelper.get_auth_algorithm_definition(self.session.auth_algorithm))
                    print('\nReceived IPMI v2.0 Trail from ' + str(sender_ip_port) + ' : \n' + str(ipmi_ciphered_msg))

                    
                else:
                    ipmi_ciphered_msg = IPMILanEnveloppe(wrapper_type = ipmi_msg.ipmi_wrapper_type, 
                                                                    ciphered_msg=ipmi_msg.message_content, 
                                                                    ipmi_sik=self.session.SIK,
                                                                    RCMP_auth_algorithm=IPMIHelper.get_auth_algorithm_definition(self.session.auth_algorithm))
                    print('\nReceived IPMI v2.0 Trail from ' + str(sender_ip_port) + ' : \n' + str(ipmi_ciphered_msg))

                if ipmi_ciphered_msg.message_type == "Request":

                    ipmi_ciphered_msg_request = IPMILanEnveloppe(rsAddr = ipmi_ciphered_msg.ipmi_lan_message.rsAddr,
                                                                    netFn = ipmi_ciphered_msg.ipmi_lan_message.netFn,
                                                                    rsLUN = ipmi_ciphered_msg.ipmi_lan_message.rsLUN,
                                                                    rqAddr = ipmi_ciphered_msg.ipmi_lan_message.rqAddr,
                                                                    rqSeq = ipmi_ciphered_msg.ipmi_lan_message.rqSeq,
                                                                    rqLUN = ipmi_ciphered_msg.ipmi_lan_message.rqLUN,
                                                                    command = ipmi_ciphered_msg.ipmi_lan_message.command,
                                                                    request_data = ipmi_ciphered_msg.ipmi_lan_message.request_data)
                    '''
                    if not self.session.console_message:
                        self.session.console_message = ipmi_ciphered_msg_request.ipmi_lan_message
                        print('Stored in session : \n' + str(ipmi_ciphered_msg_request.ipmi_lan_message))
                    else:
                        print('Already in session : \n')
                    '''
                    print('\nForged IPMIMsg request from ' + str(sender_ip_port) + ' put in session : \n' + str(ipmi_ciphered_msg_request))
                    self.session.console_message = ipmi_ciphered_msg_request.ipmi_lan_message

                    

                elif ipmi_ciphered_msg.message_type == "Response":

                    ipmi_ciphered_msg_response = IPMILanEnveloppe( ipmi_sik = self.session.SIK,
                                                                    RCMP_auth_algorithm = self.session.auth_algorithm,
                                                                    rsAddr = ipmi_ciphered_msg.ipmi_lan_message.rsAddr,
                                                                    netFn = ipmi_ciphered_msg.ipmi_lan_message.netFn,
                                                                    rsLUN = ipmi_ciphered_msg.ipmi_lan_message.rsLUN,
                                                                    rqAddr = ipmi_ciphered_msg.ipmi_lan_message.rqAddr,
                                                                    rqSeq = ipmi_ciphered_msg.ipmi_lan_message.rqSeq,
                                                                    rqLUN = ipmi_ciphered_msg.ipmi_lan_message.rqLUN,
                                                                    command = ipmi_ciphered_msg.ipmi_lan_message.command,
                                                                    completion_code = ipmi_ciphered_msg.ipmi_lan_message.completion_code,
                                                                    request_data = ipmi_ciphered_msg.ipmi_lan_message.request_data)

                    response_ipmi_msg = IPMI20TrailWrapper(ipmi_auth_type=ipmi_msg.ipmi_auth_type,
                                                            ipmi_payload_type=IPMIHelper.generate_rcmp_payload_type(is_payload_encrypted=True,
                                                                                                                    is_payload_authenticated=True, 
                                                                                                                    payload_type_definition="IPMI Message"),
                                                            ipmi_session_seq=self.session.session_sequence,
                                                            ipmi_session_id=IPMIHelper.invert_hex(self.session.get_remote_console_session_id()),
                                                            message_content=ipmi_ciphered_msg_response.serialize(),
                                                            sik=self.session.SIK,
                                                            RCMP_auth_algorithm=IPMIHelper.get_auth_algorithm_definition(self.session.auth_algorithm))
                
                    response_rcmp = RMCPMessage(rcmp_version=rmcp_message.rcmp_version,
                                            rcmp_reserved=rmcp_message.rcmp_reserved,
                                            rcmp_sequence=rmcp_message.rcmp_sequence,
                                            rcmp_message_type=rmcp_message.rcmp_message_type,
                                            rcmp_message_content=response_ipmi_msg.serialize())

                    if not response_rcmp.serialize():
                        raise AttributeError('empty')

                    print('\nForged IPMIMsg for ' + str(sender_ip_port) + ' : \n' + str(ipmi_ciphered_msg_response))
                    return [[sender_ip_port, response_rcmp.serialize()]]
                    
                else:
                    raise AttributeError('Unrecognized message type.')

                #print('Response : \n' + str(ipmi_ciphered_msg_response))

                #return response_rcmp.serialize()
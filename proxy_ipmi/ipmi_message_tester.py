from rmcp_message import RMCPMessage
from ipmi_session_wrapper import IPMISessionWrapper
from payload_ipmi_lan_req_msg import IPMILanRequest
from payload_ipmi_lan_resp_msg import IPMILanResponse
from ipmi_helper import IPMIHelper

#message received by the server
rcmp_msg_test = RMCPMessage(data = '0600ff07000000000000000000092018c88100388e04b5')

if rcmp_msg_test.rcmp_message_type == '07': #IPMI
    ipmi_msg = IPMISessionWrapper.get_IPMI_message_instance(rcmp_msg_test.rcmp_message_content)

    #ipmi v1.5 first comm
    if ipmi_msg.ipmi_wrapper_type == "IPMI v1.5":
        ipmi_msg_content = IPMILanRequest(data = ipmi_msg.message_content)

        response_ipmi_msg_content = IPMILanResponse(
            rqAddr=ipmi_msg_content.rqAddr,
            netFn='111000',  #function de +1 binaire netfn !!
            rqLUN=ipmi_msg_content.rqLUN,
            rsAddr=ipmi_msg_content.rsAddr,
            rqSeq=ipmi_msg_content.rqSeq,
            rsLUN=ipmi_msg_content.rsLUN,
            command=ipmi_msg_content.command,
            completion_code='00',#IPMIHelper.get_command_completion_code("OK"),
            response_data='0184040300000000')

    print(response_ipmi_msg_content.serialize())


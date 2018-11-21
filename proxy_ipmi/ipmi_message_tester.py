from rmcp_message import RMCPMessage
from ipmi_session_wrapper import IPMISessionWrapper
from payload_ipmi_v15 import PayloadIPMIv15

rcmp_msg_test = RMCPMessage(data = '0600ff07000000000000000000092018c88100388e04b5')

if rcmp_msg_test.rcmp_message_type == '07': #IPMI
    ipmi_msg = IPMISessionWrapper.get_IPMI_message_instance(rcmp_msg_test.rcmp_message_content)


#ipmi v1.5 first comm
if ipmi_msg.ipmi_wrapper_type == "IPMI v1.5":
    ipmi_msg_content = PayloadIPMIv15(data = ipmi_msg.message_content)

print(ipmi_msg_content)
from payload_ipmi_lan_req_msg import IPMILanRequest
from payload_ipmi_lan_resp_msg import IPMILanResponse

class IPMILanFactory():

    @classmethod
    def get_ipmi_message_instance(cls, message_type, data):
        if message_type == 'Request':
            if isinstance(data, dict):
                return IPMILanRequest(**data)
            else:
                return IPMILanRequest(data = data)
        elif message_type == 'Response':
            if isinstance(data, dict):
                return IPMILanResponse(**data)
            else:
                return IPMILanResponse(data = data)
        else:
            raise AttributeError('Invalid message type.')

from ipmi_helper import IPMIHelper
class IPMILanResponse():
    '''test'''
    def __init__(self, **keys):

        if len(keys) == 1:
            self.rqAddr = IPMILanResponse.extract_rsAddr(keys['data'])
            self.netFn, self.rqLUN = IPMILanResponse.extract_netFn_rqLUN(keys['data'])
            self.checksum1 = IPMILanResponse.extract_checksum1(keys['data'])
            self.rsAddr = IPMILanResponse.extract_rsAddr(keys['data'])
            self.rqSeq, self.rsLUN = IPMILanResponse.extract_rqSeq_rsLUN(keys['data'])
            self.command = IPMILanResponse.extract_command(keys['data'])
            self.completion_code = IPMILanResponse.extract_completion_code(keys['data'])
            self.response_data = IPMILanResponse.extract_response_data(keys['data'])
            self.checksum2 = IPMILanResponse.extract_checksum2(keys['data'])
        elif len(keys) == 9:
            self.rqAddr = keys['rqAddr']
            self.netFn = keys['netFn']
            self.rqLUN = keys['rqLUN']
            self.checksum1 = IPMIHelper.two_complement_checksum(self.rqAddr \
                                + self.hex_netFN_rqLUN())
            self.rsAddr = keys['rsAddr']
            self.rqSeq = keys['rqSeq']
            self.rsLUN = keys['rsLUN']
            self.command = keys['command']
            self.completion_code = keys['completion_code']
            self.response_data = keys['response_data']
            self.checksum2 = IPMIHelper.two_complement_checksum(self.rsAddr \
                                + self.hex_rqSeq_rsLUN() \
                                + self.command \
                                + self.completion_code \
                                + self.response_data)
        else:
            raise ValueError("No constructor with " + str(len(keys)) + " arguments.") 
  
    def __repr__(self):
        return "------- IPMILanResponse -------" \
                + "\nrqAddr : " + self.rqAddr \
                + "\nnetFn : " + self.netFn \
                + "\nrqLUN : " + self.rqLUN \
                + "\nnetFn/rqLUN : " + self.hex_netFN_rqLUN() \
                + "\nchecksum1 : " + self.checksum1 \
                + "\nrsAddr : " + self.rsAddr \
                + "\nrqSeq : " + self.rqSeq \
                + "\nrsLUN : " + self.rsLUN \
                + "\nrqSeq/rsLUN : " + self.hex_rqSeq_rsLUN() \
                + "\ncommand : " + self.command \
                + "\ncompletion_code : " + self.completion_code \
                + "\nresponse_data : " + self.response_data \
                + "\nchecksum2 : " + self.checksum2 \
                + "\nserialized : " + self.serialize()

    def hex_netFN_rqLUN(self):
        return IPMIHelper.hexify_binary_string(self.netFn[::-1], self.rqLUN[::-1])

    def hex_rqSeq_rsLUN(self):
        return IPMIHelper.hexify_binary_string(self.rqSeq[::-1], self.rsLUN[::-1])

    def serialize(self):
        return self.rqAddr \
                + self.hex_netFN_rqLUN() \
                + self.checksum1 \
                + self.rsAddr \
                + self.hex_rqSeq_rsLUN() \
                + self.command \
                + self.completion_code \
                + self.response_data \
                + self.checksum2

    @staticmethod
    def extract_rqAddr(data):
        return data[0:2]

    @staticmethod
    def extract_netFn_rqLUN(data):
        netFn_rqLUN = data[2:4]
        bits_netFn_rqLUN = IPMIHelper.get_bits(netFn_rqLUN)

        return "".join(bits_netFn_rqLUN[2:]), "".join(bits_netFn_rqLUN[0:2])

    @staticmethod
    def extract_checksum1(data):
        return data[4:6]
    
    @staticmethod
    def extract_rsAddr(data):
        return data[6:8]

    @staticmethod
    def extract_rqSeq_rsLUN(data):
        rqSeq_rsLUN = data[8:10]
        bits_rqSeq_rsLUN = IPMIHelper.get_bits(rqSeq_rsLUN)

        return "".join(bits_rqSeq_rsLUN[2:]), "".join(bits_rqSeq_rsLUN[0:2])

    @staticmethod
    def extract_command(data):
        return data[10:12]

    @staticmethod
    def extract_completion_code(data):
        return data[12:14]

    @staticmethod
    def extract_response_data(data):
        return data[14:-2]

    @staticmethod
    def extract_checksum2(data):
        return data[-2:]
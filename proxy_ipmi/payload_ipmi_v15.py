from ipmi_helper import IPMIHelper
class PayloadIPMIv15():

    def __init__(self, **keys):

        if len(keys) == 1:
            self.rsAddr = PayloadIPMIv15.extract_rsAddr(keys['data'])
            self.netFn, self.rsLUN = PayloadIPMIv15.extract_netFn_rsLUN(keys['data'])
            self.checksum1 = PayloadIPMIv15.extract_checksum1(keys['data'])
            self.rqAddr = PayloadIPMIv15.extract_rqAddr(keys['data'])
            self.rqSeq, self.rqLUN = PayloadIPMIv15.extract_rqSeq_rqLUN(keys['data'])
            self.command = PayloadIPMIv15.extract_command(keys['data'])
            self.request_data = PayloadIPMIv15.extract_request_data(keys['data'])
            self.checksum2 = PayloadIPMIv15.extract_checksum2(keys['data'])
        elif len(keys) == 8:
            self.rsAddr = keys['rsAddr']
            self.netFn = keys['netFn']
            self.rsLUN = keys['rsLUN']
            self.checksum1 = IPMIHelper.two_complement_checksum(keys['rsAddr'] \
                                + self.hex_netFN_rsLUN())
            self.rqAddr = keys['rqAddr']
            self.rqSeq = keys['rqSeq']
            self.rqLUN = keys['rqLUN']
            self.command = keys['command']
            self.request_data = keys['request_data']
            self.checksum2 = IPMIHelper.two_complement_checksum(keys['rqAddr'] \
                                + self.hex_rqSeq_rqLUN() \
                                + keys['command'] \
                                + keys['request_data'])
        else:
            raise AttributeError("Only 1 and 8 arguments constructor exists for PayloadIPMIv15 class.")
  
    def __repr__(self):
        return "------- PayloadIPMIv15 -------" \
                + "\nrsAddr : " + self.rsAddr \
                + "\nnetFn : " + self.netFn \
                + "\nrsLUN : " + self.rsLUN \
                + "\nnetFn/rsLUN : " + self.hex_netFN_rsLUN() \
                + "\nchecksum1 : " + self.checksum1 \
                + "\nrqAddr : " + self.rqAddr \
                + "\nrqSeq : " + self.rqSeq \
                + "\nrqLUN : " + self.rqLUN \
                + "\nrqSeq/rqLUN : " + self.hex_rqSeq_rqLUN() \
                + "\ncommand : " + self.command \
                + "\nrequest_data : " + self.request_data \
                + "\nchecksum2 : " + self.checksum2 \
                + "\nserialized : " + self.serialize()

    def hex_netFN_rsLUN(self):
        return IPMIHelper.hexify_binary_string(self.netFn[::-1], self.rsLUN[::-1])

    def hex_rqSeq_rqLUN(self):
        return IPMIHelper.hexify_binary_string(self.rqSeq[::-1], self.rqLUN[::-1])

    def serialize(self):
        return self.rsAddr \
                + self.hex_netFN_rsLUN() \
                + self.checksum1 \
                + self.rqAddr \
                + self.hex_rqSeq_rqLUN() \
                + self.command \
                + self.request_data \
                + self.checksum2

    @staticmethod
    def extract_rsAddr(data):
        return data[0:2]

    @staticmethod
    def extract_netFn_rsLUN(data):
        netFn_LUN = data[2:4]
        bits_netFn_LUN = IPMIHelper.get_bits(netFn_LUN)

        return "".join(bits_netFn_LUN[2:]), "".join(bits_netFn_LUN[0:2])

    @staticmethod
    def extract_checksum1(data):
        checksum = data[4:6]
        calculated_checksum = IPMIHelper.two_complement_checksum(data[0:4])

        if checksum == calculated_checksum:
            return checksum
        else:
            raise AttributeError("Extracted checksum1 vs calculated checksum mismatch.")

    @staticmethod
    def extract_rqAddr(data):
        return data[6:8]

    @staticmethod
    def extract_rqSeq_rqLUN(data):
        rqSeq_rqLUN = data[8:10]
        bits_rqSeq_rqLUN = IPMIHelper.get_bits(rqSeq_rqLUN)

        return "".join(bits_rqSeq_rqLUN[2:]), "".join(bits_rqSeq_rqLUN[0:2])

    @staticmethod
    def extract_command(data):
        return data[10:12]

    @staticmethod
    def extract_request_data(data):
        return data[12:len(data)-2]

    @staticmethod
    def extract_checksum2(data):
        checksum = data[len(data)-2:]
        calculated_checksum = IPMIHelper.two_complement_checksum(data[6:len(data)-2])

        if checksum == calculated_checksum:
            return checksum
        else:
            raise AttributeError("Extracted checksum2 vs calculated checksum mismatch.")

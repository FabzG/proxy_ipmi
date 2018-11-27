from ipmi_helper import IPMIHelper
class IPMILanRequest():

    def __init__(self, **keys):

        if len(keys) == 1:
            self.rsAddr = IPMILanRequest.extract_rsAddr(keys['data'])
            self.netFn, self.rsLUN = IPMILanRequest.extract_netFn_rsLUN(keys['data'])
            self.checksum1 = IPMILanRequest.extract_checksum1(keys['data'])
            self.rqAddr = IPMILanRequest.extract_rqAddr(keys['data'])
            self.rqSeq, self.rqLUN = IPMILanRequest.extract_rqSeq_rqLUN(keys['data'])
            self.command = IPMILanRequest.extract_command(keys['data'])
            self.request_data = IPMILanRequest.extract_request_data(keys['data'])
            self.checksum2 = IPMILanRequest.extract_checksum2(keys['data'])
        elif len(keys) == 8:
            self.rsAddr = keys['rsAddr']
            self.netFn = keys['netFn']
            self.rsLUN = keys['rsLUN']
            self.checksum1 = IPMIHelper.two_complement_checksum(self.rsAddr \
                                + self.hex_netFN_rsLUN())
            self.rqAddr = keys['rqAddr']
            self.rqSeq = keys['rqSeq']
            self.rqLUN = keys['rqLUN']
            self.command = keys['command']
            self.request_data = keys['request_data']
            self.checksum2 = IPMIHelper.two_complement_checksum(self.rqAddr \
                                + self.hex_rqSeq_rqLUN() \
                                + self.command \
                                + self.request_data)
        else:
            raise ValueError("No constructor with " + str(len(keys)) + " arguments.") 
  
    def __repr__(self):
        return "------- IPMILanRequest -------" \
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

from Crypto.Cipher import AES
import math


class RMCPMessage():

    def __init__(self, **keys):
        if len(keys) == 1:
            self.rcmp_version = self.extract_rcmp_version(keys['data'])
            self.rcmp_reserved = self.extract_rcmp_reserved(keys['data'])
            self.rcmp_sequence = self.extract_rcmp_sequence(keys['data'])
            self.rcmp_message_type = self.extract_rcmp_message_type(keys['data'])
            self.rcmp_message_content = self.extract_rcmp_message_content(keys['data'])
        elif len(keys) == 5:
            self.rcmp_version = self.extract_rcmp_version(keys['rcmp_version'])
            self.rcmp_reserved = self.extract_rcmp_reserved(keys['rcmp_reserved'])
            self.rcmp_sequence = self.extract_rcmp_sequence(keys['rcmp_sequence'])
            self.rcmp_message_type = self.extract_rcmp_message_type(keys['rcmp_message_type'])
            self.rcmp_message_content = self.extract_rcmp_message_content(keys['rcmp_message_content'])

    def __repr__(self):
        return "------- RCMPMessage -------" \
                + "\nrcmp_version : " + self.rcmp_version \
                + "\nrcmp_reserved : " + self.rcmp_reserved \
                + "\nrcmp_sequence : " + self.rcmp_sequence \
                + "\nrcmp_message_type : " + self.rcmp_message_type \
                + "\nmessage_content : " + self.rcmp_message_content

    @staticmethod
    def extract_rcmp_version(data):
        return data[0:2]

    @staticmethod
    def extract_rcmp_reserved(data):
        return data[2:4]

    @staticmethod
    def extract_rcmp_sequence(data):
        return data[4:6]

    @staticmethod
    def extract_rcmp_message_type(data):
        return data[6:8]

    @staticmethod
    def extract_rcmp_message_content(data):
        return data[8:]

    def serialize(self):
        return self.rcmp_version + self.rcmp_reserved + self.rcmp_sequence + self.rcmp_message_type + self.message_content

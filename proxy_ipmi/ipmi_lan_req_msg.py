from Crypto.Cipher import AES

class IPMILanRequestMessage():

    def __init__(self, ciphered_msg, ipmi_sik, ipmi_k2_key):
        self.ciphered_msg = ciphered_msg
        self.ipmi_sik = ipmi_sik
        self.ipmi_k2_key = ipmi_k2_key
        self.ipmi_k2_short_key = self.extract_ipmi_k2_short_key()
        self.iv = self.extract_iv()
        self.uncipherded_payload = self.decrypt_msg()
        self.rsAddr = self.extract_rsAddr()
        self.netFn = self.extract_netFn()

    def decrypt_msg(self):
        print("ipmi_ciphered_payload : " + str(self.ciphered_msg[32:]))
        aes = AES.new(bytes.fromhex(str(self.ipmi_k2_short_key)[2:-1]), AES.MODE_CBC, bytes.fromhex(str(self.iv)[2:-1]))
        return aes.decrypt(bytes.fromhex(str(self.ciphered_msg)[34:-1]))

    def extract_ipmi_k2_short_key(self):
        k2_short_key = self.ipmi_k2_key[0:32]
        print("ipmi_k2_short_key : " + str(k2_short_key))
        return k2_short_key

    def extract_rsAddr(self):
        return self.uncipherded_payload[0:1]

    def extract_netFn(self):
        netFn = self.uncipherded_payload[2:4][6:8]
        return netFn

    def extract_iv(self):
        print("ipmi_iv : " + str(self.ciphered_msg[0:32]))
        return self.ciphered_msg[0:32]
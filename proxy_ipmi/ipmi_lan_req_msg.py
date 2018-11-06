from Crypto.Cipher import AES
import math

class IPMILanRequestMessage():

    def __init__(self, ciphered_msg, ipmi_sik, ipmi_k2_key):
        self.ciphered_msg = ciphered_msg
        self.ipmi_sik = ipmi_sik
        self.ipmi_k2_key = ipmi_k2_key
        self.ipmi_k2_short_key = self.extract_ipmi_k2_short_key()
        self.iv = self.extract_iv()
        self.uncipherded_payload = self.decrypt_msg()
        self.rsAddr = self.extract_rsAddr()
        self.netFn_rslun  = self.extract_netFn_rslun()
        self.checksum_rsAdd_netFn_lun = self.extract_checksum_rsAdd_netFn_rsLun()
        self.validate_checksum_rsAdd_netFn_rsLun()
        self.rqAddr = self.extract_rqAddr()
        self.rqSeq_rqLun  = self.extract_rqSeq_rqlun()
        self.command = self.extract_command()
        self.command_data = self.extract_command_data()
        self.checksum_two = self.extract_checksum_two()
        self.validate_checksum_two()

    def decrypt_msg(self):
        print("ipmi_ciphered_payload : " + str(self.ciphered_msg[32:]))
        aes = AES.new(bytes.fromhex(str(self.ipmi_k2_short_key)[2:-1]), AES.MODE_CBC, bytes.fromhex(str(self.iv)[2:-1]))
        decrypted_msg = aes.decrypt(bytes.fromhex(str(self.ciphered_msg)[34:-1])).hex()
        return IPMILanRequestMessage.unpad_decrypted_msg(decrypted_msg)

    @staticmethod
    def unpad_decrypted_msg(message):
        last_two_chars = message[-2:]
        previous_last_two_chars = message[-4:-2]

        if last_two_chars == previous_last_two_chars:
            message = message[:len(message) - (int(last_two_chars)+1)*2]

        return message

    def extract_ipmi_k2_short_key(self):
        k2_short_key = self.ipmi_k2_key[0:32]
        print("ipmi_k2_short_key : " + str(k2_short_key))
        return k2_short_key

    def extract_rsAddr(self):
        return self.uncipherded_payload[0:2]

    def extract_rqAddr(self):
        return self.uncipherded_payload[6:8]

    def extract_netFn_rslun(self):
        netFn_lun = self.uncipherded_payload[2:4]
        return netFn_lun

    def extract_rqSeq_rqlun(self):
        rqSeq_rqlun = self.uncipherded_payload[8:10]
        return rqSeq_rqlun

    def extract_netFn(self):
        netFn = IPMILanRequestMessage.get_bits(self.netFn_rslun)[2:]
        netFn.reverse
        return "".join(netFn)

    def extract_rsLun(self):
        lun = IPMILanRequestMessage.get_bits(self.netFn_rslun)[0:2]
        lun.reverse
        return "".join(lun)

    def extract_rqSeq(self):
        rqSeq = IPMILanRequestMessage.get_bits(self.rqSeq_rqLun)[2:]
        rqSeq.reverse
        return "".join(rqSeq)

    def extract_rqLun(self):
        rqLun = IPMILanRequestMessage.get_bits(self.rqSeq_rqLun)[0:2]
        rqLun.reverse
        return "".join(rqLun)


    def extract_iv(self):
        print("ipmi_iv : " + str(self.ciphered_msg[0:32]))
        return self.ciphered_msg[0:32]

    def extract_checksum_rsAdd_netFn_rsLun(self):
        return self.uncipherded_payload[4:6]


    def validate_checksum_rsAdd_netFn_rsLun(self):
        bytes_to_check = self.rsAddr + self.netFn_rslun
        calculated_checksum = IPMILanRequestMessage.two_complement_checksum(bytes_to_check)
        if calculated_checksum != self.checksum_rsAdd_netFn_lun:
            raise AssertionError()

    def extract_command(self):
        return self.uncipherded_payload[10:12]

    def extract_command_data(self):
        return self.uncipherded_payload[12:-2]
           
    def extract_checksum_two(self):
        return self.uncipherded_payload[-2:]

    def validate_checksum_two(self):
        bytes_to_check = self.rqAddr + self.rqSeq_rqLun + self.command + self.command_data
        calculated_checksum = IPMILanRequestMessage.two_complement_checksum(bytes_to_check)
        if calculated_checksum != self.checksum_two:
            raise AssertionError()
    

    @staticmethod
    def get_bits(hex_byte):
        int_value = int(hex_byte, 16)
        bits_value = [128, 64, 32, 16, 8, 4, 2, 1]
        bits_of_byte = []
        for bit_value in bits_value:
            if int_value >= bit_value:
                bits_of_byte.append('1')
                int_value = int_value - bit_value
            else:
                bits_of_byte.append('0')

        bits_of_byte.reverse()
        return bits_of_byte

    @staticmethod
    def get_first_byte(bin_string):
        
        if bin_string[0:2] == '0b':
            bin_string = bin_string[2:]

        bits_list_value = list(bin_string)
        bits_list_value.reverse()
        bits_list_value = bits_list_value[0:8]
        bits_list_value.reverse()

        first_byte_bin = "".join(bits_list_value)
        return first_byte_bin

    @staticmethod
    def one_complement(byte_string):

        if byte_string[0:2] == '0b':
            byte_string = byte_string[2:]

        int_val = int(byte_string, 2)
        complement = 255 - int_val

        return bin(complement)[2:]

    @staticmethod
    def two_complement(byte_string):

        if byte_string[0:2] == '0b':
            byte_string = byte_string[2:]

        int_val = int(byte_string, 2)
        complement = 255 - int_val
        complement += 1

        if(complement > 255):
            return IPMILanRequestMessage.get_first_byte(bin(complement))
        else:
            bin_complement = bin(complement)[2:]
            if len(bin_complement) < 8:
                bin_complement = "0"*(8 - len(bin_complement))+bin_complement
            return bin_complement
    

    @staticmethod
    def two_complement_checksum(hex_val):

        if hex_val[0:2] == '0b':
            hex_val = hex_val[2:]

        number_of_bytes = math.ceil(len(hex_val)/2)
        bin_value = bin(int(hex_val, 16))[2:]
        if len(bin_value) < number_of_bytes*8:
            bin_value = '0'*(number_of_bytes*8 - len(bin_value)) + bin_value
        bit_array = list(bin_value)
        bit_array.reverse()
        checksum = 0

        for byte_start_pos in range(0, number_of_bytes*8, 8):
            current_byte = bit_array[byte_start_pos:byte_start_pos+8]
            current_byte.reverse()
            complement = IPMILanRequestMessage.two_complement("".join(current_byte))
            checksum += int(complement, 2)

        first_byte_checksum = IPMILanRequestMessage.get_first_byte(bin(checksum))

        checksum_two_complement = hex(int(first_byte_checksum, 2))

        return checksum_two_complement[2:]
            
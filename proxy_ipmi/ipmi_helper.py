import math
import random
import uuid

class IPMIHelper():

    @classmethod
    def hexify_binary_string(cls, *args):
        args = "".join(args)
        hex_value = hex(int(args, 2))[2:]

        hex_length_of_binary = int(len(args)/4)

        if len(hex_value) < hex_length_of_binary:
            hex_value = '0'*(hex_length_of_binary - len(hex_value))+hex_value
        
        return hex_value

    @classmethod
    def get_auth_type(cls, auth_type_byte):
        auth_type_bits = IPMIHelper.get_bits(auth_type_byte)

        useful_bits = "".join(auth_type_bits[0:4])
        int_value = int(useful_bits, 2)

        if int_value == 0:
            return "none"
        elif int_value == 1:
            return "MD2"
        elif int_value == 2:
            return "MD5"
        elif int_value == 3:
            return "reserved"
        elif int_value == 4:
            return "straight password/key"
        elif int_value == 5:
            return "OEM proprietary"
        elif int_value == 6:
            return "Format = RMCP+ (IPMI v2.0 only)"
        else:
            return "reserved"

    @classmethod
    def get_netFn_definition(cls, netFn_type_byte):

        netFn_int_value = int(netFn_type_byte[::-1], 2)

        if netFn_int_value == 0 or netFn_int_value == 1:
            return "Chassis"
        elif netFn_int_value == 2 or netFn_int_value == 3:
            return "Bridge"
        elif netFn_int_value == 4 or netFn_int_value == 5:
            return "Sensor/Event"
        elif netFn_int_value == 6 or netFn_int_value == 7:
            return "App"
        elif netFn_int_value == 8 or netFn_int_value == 9:
            return "Firmware"
        elif netFn_int_value == 10 or netFn_int_value == 11:
            return "Storage"
        elif netFn_int_value == 12 or netFn_int_value == 13:
            return "Transport"
        else:
            return "Reserved"

    @classmethod
    def get_payload_encryption(cls, payload_type_byte):
        if payload_type_byte == None:
            return None
        
        payload_type_bits = IPMIHelper.get_bits(payload_type_byte)
        encryption_status = payload_type_bits[7]

        if encryption_status == '0':
            return "unencrypted"
        elif encryption_status == '1':
            return "encrypted"
        else:
            raise AttributeError("Impossible value for payload encryption bit")

    @classmethod
    def get_payload_authentication(cls, payload_type_byte):
        if payload_type_byte == None:
            return None
        
        payload_type_bits = IPMIHelper.get_bits(payload_type_byte)
        encryption_status = payload_type_bits[6]

        if encryption_status == '0':
            return "unauthenticated"
        elif encryption_status == '1':
            return "authenticated"
        else:
            raise AttributeError("Impossiblme value for payload authentication bit")

    @classmethod
    def get_payload_type(cls, payload_type_byte):
        if payload_type_byte == None:
            return None
        
        payload_type_bits = IPMIHelper.get_bits(payload_type_byte)
        encryption_status = int("".join(payload_type_bits[0:6]), 2)

        if encryption_status == 0:
            return "IPMI Message"
        elif encryption_status == 1:
            return "SOL (serial over LAN)"
        elif encryption_status == 2:
            return "OEM Explicit"
        elif encryption_status == 16:
            return "RMCP+ Open Session Request"
        elif encryption_status == 17:
            return "RMCP+ Open Session Response"
        elif encryption_status == 18:
            return "RAKP Message 1"
        elif encryption_status == 19:
            return "RAKP Message 2"
        elif encryption_status == 20:
            return "RAKP Message 3"
        elif encryption_status == 21:
            return "RAKP Message 4"
        elif encryption_status >= 32 and encryption_status <= 39:
            return "OEM Payload"
        else:
            return "reserved"
    
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
            return IPMIHelper.get_first_byte(bin(complement))
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
            complement = IPMIHelper.two_complement("".join(current_byte))
            checksum += int(complement, 2)

        first_byte_checksum = IPMIHelper.get_first_byte(bin(checksum))

        checksum_two_complement = hex(int(first_byte_checksum, 2))[2:]

        if len(checksum_two_complement) < 2:
            checksum_two_complement = '0'+checksum_two_complement

        return checksum_two_complement

    @staticmethod
    def invert_hex(hex_val):
        inverted = []
        for pos in range(0, len(hex_val), 2):
            inverted.append(hex_val[pos:pos+2])

        inverted.reverse()

        return "".join(inverted)

    @staticmethod
    def generate_rakp_remote_console_random_number():
        min_value = 0
        max_value = 16**32

        random_number = random.randrange(min_value, max_value+1)

        hex_random = hex(random_number)[2:]

        if len(hex_random) < 32:
            hex_random = '0'*(32 - len(hex_random)) + hex_random

        return hex_random

    @staticmethod
    def unpad_ipmi_lan_decrypted_msg(message):
        last_two_chars = message[-2:]
        previous_last_two_chars = message[-4:-2]

        if last_two_chars == previous_last_two_chars:
            message = message[:len(message) - (int(last_two_chars)+1)*2]

        return message


    @staticmethod
    def get_requested_maximum_privilege_definition(hex_val):
        maximum_privileges = {
            '00' :'Highest level matching proposed algorithms',
            '01' : 'CALLBACK level',
            '02' : 'USER level',
            '03' : 'OPERATOR level',
            '04' : 'ADMINISTRATOR level',
            '05' : 'OEM Proprietary level'
        }

        try:
            return maximum_privileges[hex_val]
        except:
            return "Unkown level"

    @staticmethod
    def get_auth_algorithm_definition(bits_string_val):
        int_val = int(bits_string_val, 2)

        if int_val == 0:
            return "RAKP-none"
        elif int_val == 1:
            return "RAKP-HMAC-SHA1"
        elif int_val == 2:
            return "RAKP-HMAC-MD5"
        elif int_val == 3:
            return "RAKP-HMAC-SHA256"
        elif int_val >= 192 and int_val <= 255:
            return "OEM"
        else:
            return "reserved"

    @staticmethod
    def get_integrity_algorithm_definition(bits_string_val):
        int_val = int(bits_string_val, 2)

        if int_val == 0:
            return "none"
        elif int_val == 1:
            return "HMAC-SHA1-96"
        elif int_val == 2:
            return "HMAC-MD5-128"
        elif int_val == 3:
            return "MD5-128"
        elif int_val == 4:
            return "HMAC-SHA256-128"
        elif int_val >= 192 and int_val <= 255:
            return "OEM"
        else:
            return "reserved"

    @staticmethod
    def get_confidentiality_algorithm_definition(bits_string_val):
        int_val = int(bits_string_val, 2)

        if int_val == 0:
            return "none"
        elif int_val == 1:
            return "AES-CBC-128"
        elif int_val == 2:
            return "xRC4-128"
        elif int_val == 3:
            return "xRC4-40"
        elif int_val >= 48 and int_val <= 63:
            return "OEM"
        else:
            return "reserved"
    
    @staticmethod
    def get_requested_max_privilege_level_definition(bits_string_val):
        int_val = int(bits_string_val, 2)

        if int_val == 0:
            return "reserved"
        elif int_val == 1:
            return "CALLBACK level"
        elif int_val == 2:
            return "USER level"
        elif int_val == 3:
            return "OPERATOR level"
        elif int_val == 4:
            return "ADMINISTRATOR level"
        elif int_val == 5:
            return "OEM Proprietary level"
        else:
            raise AttributeError('Unknown requested_max_privilege_level_definition')

    @staticmethod
    def get_username_human_readable(hex_val):
        str_val = bytes.fromhex(hex_val).decode("utf8")

        return str_val

    
    @staticmethod
    def get_rcmp_status_code_definition(hex_val):
        maximum_privileges = {
            '00' :'No errors',
            '01' : 'Insufficient resources to create a session',
            '02' : 'Invalid session ID',
            '03' : 'Invalid payload type',
            '04' : 'Invalid authentication algorithm',
            '05' : 'Invalid integrity algorithm',
            '06' : 'No matching authentication payload',
            '07' : 'No matching integrity payload',
            '08' : 'Inactive session id',
            '09' : 'Invalid role',
            '0a' : 'Unauthorized role or privilege level requested',
            '0b' : 'Insufficient resources to create a session at the requested role',
            '0c' : 'Invalid name length',
            '0d' : 'Unauthorized name',
            '0e' : 'Unauthorized GUID',
            '0f' : 'Invalid integrity check value',
            '10' : 'Invalid confidentiality algorithm',
            '11' : 'No Cipher suite match with proposed security algorithm',
            '12' : 'Illegal or unrecognized parameter'
        }

        try:
            return maximum_privileges[hex_val]
        except:
            return "Reserved for future definition"

    @staticmethod
    def generate_managed_system_random_number():
        lower_bound = 0
        upper_bound = int('FF'*16, 16)

        random_number = random.randint(lower_bound, upper_bound)

        return hex(random_number)[2:]


    @staticmethod
    def generate_managed_system_GUID():
        return uuid.uuid4().hex

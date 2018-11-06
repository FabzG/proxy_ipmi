import pytest
from proxy_ipmi.ipmi_lan_req_msg import IPMILanRequestMessage

@pytest.fixture()
def ipmi_lan_msg():
    return IPMILanRequestMessage(ciphered_msg = b'2bbeba34c433ffe01418fbbc6af98458f0d17b1003363a316334211f4ded488c', ipmi_sik = b'a81c00dca294467b52e0d087d13ab32f532cf5cc', ipmi_k2_key = b'6700aaab16591613a546f21f5ef54dd15e99d0af')

def test_ipmi_lan_req_msg_get_uncipherded_data(ipmi_lan_msg):
    assert ipmi_lan_msg.uncipherded_payload.hex() == '2000e08124015a010203040506070808'

def test_ipmi_lan_req_msg_get_rsAddr(ipmi_lan_msg):
    assert ipmi_lan_msg.rsAddr.hex() == '20'

def test_ipmi_lan_req_msg_get_netFn(ipmi_lan_msg):
    assert ipmi_lan_msg.netFn == '00'

def test_get_first_byte():
    test_bin = '0b1000110111'
    assert IPMILanRequestMessage.get_first_byte(test_bin) == "00110111" #0b00110111 

def test_one_complement():
    test_bin = '0b00110111'
    assert IPMILanRequestMessage.one_complement(test_bin) == "11001000" #0b11001000

def test_two_complement():
    test_bin = '0b00110111' #55
    assert IPMILanRequestMessage.two_complement(test_bin) == "11001001" #0b11001001 = 255 - 55 + 1

def test_two_complement_max():
    test_bin = '0b11111111' #255
    assert IPMILanRequestMessage.two_complement(test_bin) == "00000001" #0b11001001 = 255 - 255 + 1

def test_two_complement_zero():
    test_bin = '0b00000000' #0
    assert IPMILanRequestMessage.two_complement(test_bin) == "00000000" #0b00000000 = 255 - 0 + 1 = 256 = 0 on first byte


def test_two_complement_checksum():
    test_hex = '2020'
    assert IPMILanRequestMessage.two_complement_checksum(test_hex) == 'c0'

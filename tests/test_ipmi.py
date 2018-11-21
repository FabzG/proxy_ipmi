import pytest
from proxy_ipmi.rmcp_message import RMCPMessage

@pytest.fixture()
def ipmi_lan_msg():
    return RMCPMessage(data = b'2bbeba34c433ffe01418fbbc6af98458f0d17b1003363a316334211f4ded488c')

def test_ipmi_lan_req_msg_get_uncipherded_data(ipmi_lan_msg):
    assert ipmi_lan_msg.uncipherded_payload == '2000e08124015a' #full decrypted : 2000e08124015a010203040506070808

def test_ipmi_lan_req_msg_get_rsAddr(ipmi_lan_msg):
    assert ipmi_lan_msg.rsAddr == '20'

def test_ipmi_lan_req_msg_get_netFn_rslun(ipmi_lan_msg):
    assert ipmi_lan_msg.netFn_rslun == '00'

def test_ipmi_lan_req_msg_get_netFn(ipmi_lan_msg):
    assert ipmi_lan_msg.extract_netFn() == '000000'

def test_ipmi_lan_req_msg_get_rsLun(ipmi_lan_msg):
    assert ipmi_lan_msg.extract_rsLun() == '00'

def test_ipmi_lan_req_msg_get_rqSeq(ipmi_lan_msg):
    assert ipmi_lan_msg.extract_rqSeq() == '100100'

def test_ipmi_lan_req_msg_get_rqLun(ipmi_lan_msg):
    assert ipmi_lan_msg.extract_rqLun() == '00'

def test_ipmi_lan_req_msg_get_command(ipmi_lan_msg):
    assert ipmi_lan_msg.command == '01'

def test_ipmi_lan_req_msg_get_command_data(ipmi_lan_msg):
    assert ipmi_lan_msg.command_data == ''

def test_ipmi_lan_req_msg_get_rqAddr(ipmi_lan_msg):
    assert ipmi_lan_msg.rqAddr == '81'

def test_ipmi_lan_req_msg_get_rqSec_rqLun(ipmi_lan_msg):
    assert ipmi_lan_msg.rqSeq_rqLun == '24'

def test_ipmi_lan_req_msg_checksum_one(ipmi_lan_msg):
    try:
        ipmi_lan_msg.validate_checksum_rsAdd_netFn_rsLun()
    except:
        pytest.fail("Exception in checksum 1 comparison")

def test_ipmi_lan_req_msg_checksum_two(ipmi_lan_msg):
    try:
        ipmi_lan_msg.validate_checksum_two()
    except:
        pytest.fail("Exception in checksum 2 comparison")

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


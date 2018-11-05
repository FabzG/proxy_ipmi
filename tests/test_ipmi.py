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
    assert ipmi_lan_msg.netFn == b''
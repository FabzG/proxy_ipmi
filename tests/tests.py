import pytest

@pytest.fixture()
def ipmi_lan_msg():
    return IPMILanRequestMessage(ciphered_msg = b'2bbeba34c433ffe01418fbbc6af98458f0d17b1003363a316334211f4ded488c', ipmi_sik = b'a81c00dca294467b52e0d087d13ab32f532cf5cc', ipmi_k2_key = b'6700aaab16591613a546f21f5ef54dd15e99d0af')

def test_ipmi_lan_req_msg_get_uncipherded_data(ipmi_lan_msg):
    ipmi_lan_msg = get(ipmi_lan_msg, 0)
    assert ipmi_lan_msg.uncipherded_data == b'2000E08124015A010203040506070808'

def test_ipmi_lan_req_msg_get_rsAddr(ipmi_lan_msg):
    ipmi_lan_msg = get(ipmi_lan_msg, 0)
    assert ipmi_lan_msg.rsAddr == b'2b'

def test_ipmi_lan_req_msg_get_netFn(ipmi_lan_msg):
    ipmi_lan_msg = get(ipmi_lan_msg, 0)
    assert ipmi_lan_msg.rsAddr == b''
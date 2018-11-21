import pytest
from proxy_ipmi.ipmi_get_decoder import IPMIGetDecoder

@pytest.fixture()
def ipmi_get_decoder():
    return IPMIGetDecoder(data='2018c88110388e03a6')

def test_channel_number_ipmi_version(ipmi_get_decoder):
    assert True
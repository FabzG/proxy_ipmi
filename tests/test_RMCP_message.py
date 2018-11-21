import pytest
from proxy_ipmi. import IPMILanRequestMessage

@pytest.fixture()
def ipmi_lan_msg():
    return RCMP(ciphered_msg = b'2bbeba34c433ffe01418fbbc6af98458f0d17b1003363a316334211f4ded488c', ipmi_sik = b'a81c00dca294467b52e0d087d13ab32f532cf5cc', ipmi_k2_key = b'6700aaab16591613a546f21f5ef54dd15e99d0af')

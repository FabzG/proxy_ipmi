from proxy_ipmi.ipmi_lan_req_msg import IPMILanRequestMessage

tipmi = IPMILanRequestMessage(ciphered_msg = b'2bbeba34c433ffe01418fbbc6af98458f0d17b1003363a316334211f4ded488c', ipmi_sik = b'a81c00dca294467b52e0d087d13ab32f532cf5cc', ipmi_k2_key = b'6700aaab16591613a546f21f5ef54dd15e99d0af')
print(tipmi.ipmi_k2_key)
print(tipmi.ciphered_msg)
print(tipmi.uncipherded_payload.hex())
print("RSAddr : " + str(tipmi.rsAddr.hex()))
print("NetFn : " + str(tipmi.netFn.hex()))
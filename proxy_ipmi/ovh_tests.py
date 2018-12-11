import ovh
import json
from lxml import etree
import io
import re
import time

machine_name = 'ns6914969.ip-145-239-129.eu'

client = ovh.Client(
    endpoint='ovh-eu',               # Endpoint of API OVH Europe (List of available endpoints)
    application_key='DHDoQCdshKnFA3pk',    # Application Key
    application_secret='igNicOWubgJRt60TfoHMKnc8UqWg2aB5', # Application Secret
    consumer_key='ehAEVxHnRidHQmr2t7CWmuaknatO9rMQ',       # Consumer Key
    
)

result_ipmi_ip_request = client.post('/dedicated/server/'+machine_name+'/features/ipmi/access', 
    ttl='15', # Required: Session access time to live in minutes (type: dedicated.server.CacheTTLEnum),
    type= "kvmipJnlp",#  Required: IPMI console access (type: dedicated.server.IpmiAccessTypeEnum)
    ipToAllow='80.215.78.25',
)

result_task = client.get('/dedicated/server/'+machine_name+'/task/' + str(result_ipmi_ip_request["taskId"]))

while result_task["status"] != 'done' and result_task["status"] != 'ovhError':
    result_task = client.get('/dedicated/server/'+machine_name+'/task/' + str(result_ipmi_ip_request["taskId"]))
    print(result_task)
    time.sleep(1)

result = client.get('/dedicated/server/'+machine_name+'/features/ipmi/access', 
    type='kvmipJnlp'#, // Required: IPMI console access (type: dedicated.server.IpmiAccessTypeEnum)
)

def get_ip_from_ovh_ipmi_response(json_response):

    value_field = json_response["value"]
    re.DOTALL
    match = re.search('.*>[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}<.*', value_field)

    matched_string = value_field[match.start():match.end()]
    low_index = matched_string.index(">")+1
    high_index = matched_string.index("<", low_index)
    ip = matched_string[low_index:high_index]

    return ip

print(get_ip_from_ovh_ipmi_response(result))

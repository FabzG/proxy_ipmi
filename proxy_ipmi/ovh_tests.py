import ovh
import json
from lxml import etree
import io
import re
'''
client = ovh.Client(
    endpoint='ovh-eu',               # Endpoint of API OVH Europe (List of available endpoints)
    application_key='DHDoQCdshKnFA3pk',    # Application Key
    application_secret='igNicOWubgJRt60TfoHMKnc8UqWg2aB5', # Application Secret
    consumer_key='ehAEVxHnRidHQmr2t7CWmuaknatO9rMQ',       # Consumer Key
)

result = client.post('/dedicated/server/ns3043313.ip-51-255-91.eu/features/ipmi/access', 
    ttl='1', # Required: Session access time to live in minutes (type: dedicated.server.CacheTTLEnum),
    type= "kvmipJnlp"#  Required: IPMI console access (type: dedicated.server.IpmiAccessTypeEnum)
)

# Pretty print
print(json.dumps(result, indent=4))

result = client.get('/dedicated/server/ns3043313.ip-51-255-91.eu/task/118548283')

# Pretty print
print(json.dumps(result, indent=4))

result = client.get('/dedicated/server/ns3043313.ip-51-255-91.eu/features/ipmi/access', 
    type='kvmipJnlp'#, // Required: IPMI console access (type: dedicated.server.IpmiAccessTypeEnum)
)

# Pretty print
print(json.dumps(result, indent=4))
'''


json_content = {"expiration": "2018-11-28T12:24:32+01:00", "value": "<jnlp spec=\"1.0+\" codebase=\"https://74070979f50845b4999b10b178b98fe7.eri1-1.ipmi.ovh.net/\">\n  <information>\n    <title>ATEN Java iKVM Viewer</title>\n    <vendor>ATEN</vendor>\n    <description>Java Web Start Application</description>\n  </information>\n\n  <security>\n   <all-permissions/>\n  </security>\n\n  <resources>\n    <property name=\"jnlp.packEnabled\" value=\"true\"/>\n    <j2se version=\"1.6.0+\" initial-heap-size=\"128M\" max-heap-size=\"128M\" java-vm-args=\"-XX:PermSize=32M -XX:MaxPermSize=32M\"/>\n    <jar href=\"iKVM__V1.69.26.0x0.jar\" download=\"eager\" main=\"true\"/>\n  </resources>\n\n  <resources os=\"Windows\" arch=\"x86\">\n    <nativelib href=\"libwin_x86__V1.0.8.jar\" download=\"eager\"/>\n  </resources>\n  <resources os=\"Windows\" arch=\"x86_64\">\n    <nativelib href=\"libwin_x86_64__V1.0.8.jar\" download=\"eager\"/>\n  </resources>\n  <resources os=\"Windows\" arch=\"amd64\">\n<nativelib href=\"libwin_x86_64__V1.0.8.jar\" download=\"eager\"/>\n  </resources>\n\n  <resources os=\"Linux\" arch=\"i386\">\n    <nativelib href=\"liblinux_x86__V1.0.8.jar\" download=\"eager\"/>\n    <property name=\"jnlp.packEnabled\" value=\"true\"/>\n    <property name=\"jnlp.versionEnabled\" value=\"true\"/>\n  </resources>\n  <resources os=\"Linux\" arch=\"x86\">\n <nativelib href=\"liblinux_x86__V1.0.8.jar\" download=\"eager\"/>\n    <property name=\"jnlp.packEnabled\" value=\"true\"/>\n    <property name=\"jnlp.versionEnabled\" value=\"true\"/>\n</resources>\n  <resources os=\"Linux\" arch=\"x86_64\">\n    <nativelib href=\"liblinux_x86_64__V1.0.8.jar\" download=\"eager\"/>\n    <property name=\"jnlp.packEnabled\" value=\"true\"/>\n    <property name=\"jnlp.versionEnabled\" value=\"true\"/>\n  </resources>\n  <resources os=\"Linux\" arch=\"amd64\">\n    <nativelib href=\"liblinux_x86_64__V1.0.8.jar\" download=\"eager\"/>\n    <property name=\"jnlp.packEnabled\" value=\"true\"/>\n    <property name=\"jnlp.versionEnabled\" value=\"true\"/>\n  </resources>\n\n  <resources os=\"Mac OS X\" arch=\"x86_64\">\n    <nativelib href=\"libmac_x86_64__V1.0.8.jar\" download=\"eager\"/>\n  </resources>\n\n  <application-desc main-class=\"tw.com.aten.ikvm.KVMMain\">\n    <argument>178.32.242.1</argument>\n    <argument>nxghkmeofvfwpcag</argument>\n    <argument>nxghkmeofvfwpcag</argument>\n\t<argument>null</argument>\n    <argument>5900</argument>\n    <argument>623</argument>\n    <argument>0</argument>\n    <argument>0</argument>\n    <argument>0</argument>\n    <argument>3520</argument>\n  </application-desc>\n</jnlp>\n"}


def get_ip_from_ovh_ipmi_response(json_response):
    xml_content = io.StringIO(json_content["value"])

    xml_tree = etree.parse(xml_content)
    appli_desc = xml_tree.xpath('/jnlp/application-desc/argument')

    ip = ''

    for attribute in appli_desc:
        if re.match('^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$', attribute.text):
            ip = attribute.text

    return ip

print(get_ip_from_ovh_ipmi_response(json_content))
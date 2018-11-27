import socket as soc
import time
from ipmi_session import IPMISession
from session_orchestrator import SessionOrchestrator


server = ''
serverPort = 623
sockobj = soc.socket(soc.AF_INET, soc.SOCK_DGRAM)
sockobj.bind((server, serverPort))

orchestrator = SessionOrchestrator()

while True:
    message, clientaddress = sockobj.recvfrom(2048)
   
    
    print("I got the client's address as: ", clientaddress)
    print("I got the message")
    print(message.hex())
    
    response = orchestrator.treat_message(message.hex())

    print("I respond")
    print(response)

    sockobj.sendto(bytes.fromhex(response), clientaddress)


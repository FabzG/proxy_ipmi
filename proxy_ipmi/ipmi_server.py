import socket as soc
import time
from threading import Thread
from ipmi_session import IPMISession
from session_orchestrator import SessionOrchestrator
from ipmi_thread import IPMIThread
from ipmi_server_thread import IPMIServerThread
import queue


server = ''
serverPort = 623
sockobj = soc.socket(soc.AF_INET, soc.SOCK_DGRAM)
sockobj.bind((server, serverPort))


orchestrator = SessionOrchestrator()
commands_to_run = queue.LifoQueue()
treat_thread = IPMIServerThread(commands_to_run, sockobj)
treat_thread.start()

while True:
    message, clientaddress = sockobj.recvfrom(2048)

    
    #print("I got the client's address as: ", clientaddress)
    #print("I got the message " + message.hex() + " from " + str(clientaddress))
    
    tread = IPMIThread(message, orchestrator, clientaddress, commands_to_run)
    tread.start()

    
    #response = orchestrator.treat_message(message.hex())

    #print("I respond")

    #sockobj.sendto(bytes.fromhex(response), clientaddress)


from threading import Thread
from session_orchestrator import SessionOrchestrator
import time

class IPMIServerThread(Thread):
    
    def __init__(self, command_queue, socket):
        Thread.__init__(self)
        self.command_queue = command_queue
        self.socket = socket
    
    def run(self):

        while True:
            if not self.command_queue.empty():
                command = self.command_queue.get()
                if command[1] != None:
                    self.socket.sendto(bytes.fromhex(command[1]), command[0])
                print("sent command " + str(command[1]))
            
            time.sleep(1)
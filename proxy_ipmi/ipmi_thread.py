from threading import Thread
from session_orchestrator import SessionOrchestrator

class IPMIThread(Thread):
    
    def __init__(self, msg, orchestrator, ip, commands_to_run):
        Thread.__init__(self)
        self.msg = msg
        self.orchestrator = orchestrator
        self.ip = ip
        self.commands_to_run = commands_to_run

    def run(self):
        resp = self.orchestrator.treat_message(self.msg.hex())
        resp_msg = [self.ip, resp]
        print("in thresad" + str(resp_msg[0]) + str(resp_msg[1]))
        self.commands_to_run.put(resp_msg)
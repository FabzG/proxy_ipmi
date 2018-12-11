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
        resp = self.orchestrator.treat_message(self.msg.hex(), self.ip)

        if resp and len(resp) > 0:
            for response in resp:
                print("Put message : " + str(response[0]) + str(response[1]))
                self.commands_to_run.put(response)
        else:
            print("No message to put in queue : session stored")

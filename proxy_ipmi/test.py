import time
from threading import Thread
import gc

class Timeout(Thread):

    def __init__(self, class_reference, timeout):
        Thread.__init__(self)
        self.timeout = timeout
        self.class_reference = class_reference

    def run(self):
        time.sleep(self.timeout)
        self.class_reference = None

class Test:
    def __init__(self):
        self.test = 'lol'
        
class SessionPool:
    def __init__(self, session_number):
        self.sessions_available = []
        self.sessions_in_use = []
        self.thread = Timeout(self.test, 3)
        self.thread.start()

    def get_session(self):
        session = self.sessions_available.pop()
        self.sessions_in_use.append(session)
        


essai = ClassInstancier(5)
print(essai.test.test)
time.sleep(5)
print(essai.test.test)

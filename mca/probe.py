import time
import threading


class Probe:

    def __init__(self, flowid, ttl, dst, probe_id=0):
        self.probe_id = probe_id
        self.timeout = 2.0
        self.probe_scapy = None
        self.sent_time = None
        self.attempts = 0
        self.flowid = flowid
        self.ttl = ttl
        self.dst = dst

        # Answer
        self.answer_ip = '*' + str(ttl)
        self.answer_time = None
        self.answer_scapy = None
        self.answer_type = None
        self.answer_wait = threading.Condition()

    def timed_out(self):
        now = time.time()
        if now >= (self.sent_time + self.timeout):
            return True
        return False

    def wait(self):
        self.answer_wait.acquire()
        now = time.time()
        self.answer_wait.wait(self.timeout - (now - self.sent_time))
        self.answer_wait.release()

    def notify(self):
        self.answer_wait.acquire()
        self.answer_wait.notify()
        self.answer_wait.release()

    def set_attempt(self, probe_scapy):
        self.probe_scapy = probe_scapy
        self.sent_time = probe_scapy.sent_time
        self.attempts += 1

    def set_answer(self, ip, packet, answer_type):
        self.answer_ip = ip
        self.answer_time = packet.time
        self.answer_scapy = packet
        self.answer_type = answer_type

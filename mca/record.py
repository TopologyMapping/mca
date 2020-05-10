import ipaddress
import struct


class Record:

    def __init__(self):
        self.data = []
        self.file = None

    def _write_uint8(self, value):
        self.file.write(struct.pack('>B', value))

    def _write_uint16(self, value):
        self.file.write(struct.pack('>H', value))

    def _write_uint32(self, value):
        self.file.write(struct.pack('>I', value))

    def _write_uint64(self, value):
        self.file.write(struct.pack('>Q', value))

    def _write_uint128(self, value):
        self.file.write(struct.pack('>QQ', value >> 64, value & (2 ** 64 - 1)))

    def _write_bool(self, value):
        self._write_uint8(int(value))

    def _write_ipaddr(self, addr):
        if '*' in addr:
            self._write_uint8(0)
            self._write_string(addr)
        else:
            ip = ipaddress.ip_address(addr)
            self._write_uint8(ip.version)
            if ip.version == 4:
                self._write_uint32(int(ip))
            else:
                self._write_uint128(int(ip))

    def _write_string(self, s):
        self._write_uint32(len(s))
        self.file.write(s.encode('utf-8'))

    def _write_string_list(self, str_list):
        self._write_uint32(len(str_list))
        for s in str_list:
            self._write_string(s)

    def _write_ipaddr_list(self, ipaddr_list):
        self._write_uint32(len(ipaddr_list))
        for ip in ipaddr_list:
            self._write_ipaddr(ip)

    def _write_time(self, t):
        t = t if t is not None else 0
        t = int(round(t * 1000))
        self._write_uint64(t)

    def _write_bytes(self, b):
        self._write_uint32(len(b))
        self.file.write(b)

    def write_probe_answer(self, pa):
        self._write_time(
            pa.sent_time if pa.sent_time is not None else 0
        )
        self._write_bytes(
            bytes(pa.probe_scapy) if pa.sent_time is not None else b''
        )
        self._write_time(
            pa.answer_time if pa.answer_time is not None else 0
        )
        self._write_bytes(
            bytes(pa.answer_scapy) if pa.answer_time is not None else b''
        )

        # Write number of attempts
        self._write_uint32(pa.attempts)

        # Write flowids
        self._write_uint32(len(pa.flowid))
        for f in pa.flowid:
            self._write_uint32(f)

    def write_probe_answer_list(self, pa_list):
        self._write_uint32(len(pa_list))
        for pa in pa_list:
            self.write_probe_answer(pa)

    def _write_halting_list(self, halting_list):
        self._write_uint32(len(halting_list))
        for e in halting_list:
            self._write_ipaddr(e[0])
            self._write_string(e[1])

    def write_record(self, record_type, content):
        self.data.append((record_type, content))

    def dump(self, filename):
        fn = {
            'ipaddr':       self._write_ipaddr,
            'string':       self._write_string,
            'string-list':  self._write_string_list,
            'uint8':        self._write_uint8,
            'uint16':       self._write_uint16,
            'uint32':       self._write_uint32,
            'uint64':       self._write_uint64,
            'uint128':      self._write_uint128,
            'time':         self._write_time,
            'bool':         self._write_bool,
            'ipaddr-list':  self._write_ipaddr_list,
            'probe-list':   self.write_probe_answer_list,
            'halting-list': self._write_halting_list,
        }

        type_id = {
            'header': 1,
            'stats': 2,
            'next_hops': 3,
            'classify': 4,
            'node_control': 5,
            'paris_traceroute': 6,
            'halting': 7
        }

        self.file = open(filename, 'wb')

        for record in self.data:
            record_type = record[0]
            record_data = record[1]

            self._write_uint16(type_id[record_type])
            for c in record_data:
                fn[c[0]](c[1])

        self.file.close()

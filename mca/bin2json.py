import base64
import ipaddress
import json
import struct


class BinaryToJson():

    def __init__(self, filename, out_filename):
        records = {
            1: {'name': 'header', 'data': [
                {'type': 'ipaddr',      'name': 'dst_ip'},
                {'type': 'ipaddr',      'name': 'src_ip'},
                {'type': 'ipaddr',      'name': 'gateway'},
                {'type': 'string',      'name': 'interface'},
                {'type': 'string',      'name': 'bpf_filter'},
                {'type': 'string',      'name': 'probe_type'},
                {'type': 'uint32',      'name': 'pps'},
                {'type': 'uint8',       'name': 'max_attempts'},
                {'type': 'uint8',       'name': 'wait_timeout'},
                {'type': 'uint8',       'name': 'alpha'},
                {'type': 'uint8',       'name': 'max_ttl'},
                {'type': 'uint8',       'name': 'gap_limit'},
                {'type': 'uint16',      'name': 'max_nh'},
                {'type': 'uint16',      'name': 'max_border'},
                {'type': 'string-list', 'name': 'fid_fields'},
            ]},

            2: {'name': 'stats', 'data': [
                {'type': 'time',   'name': 'init_time'},
                {'type': 'time',   'name': 'finish_time'},
                {'type': 'uint32', 'name': 'sent_packets'},
                {'type': 'uint32', 'name': 'matched_packets'},
                {'type': 'uint32', 'name': 'matches_on_retry'},
                {'type': 'uint32', 'name': 'retries'},
                {'type': 'uint8',  'name': 'halt_ttl'}
            ]},

            3: {'name': 'next_hops', 'data': [
                {'type': 'ipaddr',      'name': 'ip'},
                {'type': 'uint8',       'name': 'ttl'},
                {'type': 'probe-list',  'name': 'probes'},
                {'type': 'ipaddr-list', 'name': 'next_hops'}
            ]},

            4: {'name': 'classify', 'data': [
                {'type': 'ipaddr',     'name': 'ip'},
                {'type': 'uint8',      'name': 'ttl'},
                {'type': 'string',     'name': 'field'},
                {'type': 'probe-list', 'name': 'probes'},
                {'type': 'uint8',      'name': 'result'}
            ]},

            5: {'name': 'node_control', 'data': [
                {'type': 'ipaddr',      'name': 'ip'},
                {'type': 'uint8',       'name': 'ttl'},
                {'type': 'probe-list',  'name': 'probes'},
            ]},

            6: {'name': 'paris_traceroute', 'data': [
                {'type': 'probe-list',  'name': 'probes'},
                {'type': 'ipaddr-list', 'name': 'result'},
                {'type': 'uint8',       'name': 'max_ttl'}
            ]},

            7: {'name': 'halting', 'data': [
                {'type': 'halting_list', 'name': 'halting_causes'}
            ]}
        }

        data = []

        self.f = open(filename, 'rb')
        while True:
            if not self.f.read(2):
                break
            self.f.seek(-2, 1)
            record_type = self._read_uint16()
            record_name = records[record_type]['name']
            record_data = self._read_record(records[record_type]['data'])

            data.append({'name': record_name, 'data': record_data})

        self.f.close()

        with open(out_filename, 'w') as f:
            f.write(json.dumps(data))

    def _read_uint8(self):
        value = self.f.read(1)
        return struct.unpack('>B', value)[0]

    def _read_uint16(self):
        value = self.f.read(2)
        return struct.unpack('>H', value)[0]

    def _read_uint32(self):
        value = self.f.read(4)
        return struct.unpack('>I', value)[0]

    def _read_uint64(self):
        value = self.f.read(8)
        return struct.unpack('>Q', value)[0]

    def _read_uint128(self):
        value = self.f.read(16)
        v1, v2 = struct.unpack('>QQ', value)
        return (v1 << 64) | v2

    def _read_bool(self):
        v = self._read_uint8()
        return bool(v)

    def _read_ipaddr(self):
        ip_version = self._read_uint8()
        if ip_version == 0:
            return self._read_string()
        elif ip_version == 4:
            return str(ipaddress.IPv4Address(self._read_uint32()))
        else:
            return str(ipaddress.IPv6Address(self._read_uint128()))

    def _read_halting_list(self):
        n = self._read_uint32()
        causes = {}
        for s in range(n):
            ip_addr = self._read_ipaddr()
            cause = self._read_string()
            causes[ip_addr] = cause
        return causes

    def _read_ipaddr_list(self):
        n = self._read_uint32()
        ip_list = []
        for s in range(n):
            ip_list.append(self._read_ipaddr())
        return ip_list

    def _read_string(self):
        str_size = self._read_uint32()
        if str_size == 0:
            return ''
        return self.f.read(str_size).decode('utf-8')

    def _read_bytes(self):
        s = self._read_uint32()
        if s == 0:
            return b''
        return self.f.read(s)

    def _read_string_list(self):
        n_strs = self._read_uint32()
        str_list = []
        for s in range(n_strs):
            str_list.append(self._read_string())
        return str_list

    def _read_probe(self):
        result = {
            'probe_time': self._read_time(),
            'probe': base64.b64encode(self._read_bytes()).decode('utf-8'),
            'answer_time': self._read_time(),
            'answer': base64.b64encode(self._read_bytes()).decode('utf-8'),
            'attempts': self._read_uint32(),
            'flowid': []
        }

        # Read flowids
        number_flowids = self._read_uint32()
        for i in range(number_flowids):
            result['flowid'].append(self._read_uint32())

        return result

    def _read_probe_list(self):
        n = self._read_uint32()
        probe_list = []
        for s in range(n):
            probe_list.append(self._read_probe())
        return probe_list

    def _read_time(self):
        return self._read_uint64()

    def _read_record(self, record_format):
        fn = {
            'ipaddr':       self._read_ipaddr,
            'string':       self._read_string,
            'string-list':  self._read_string_list,
            'uint8':        self._read_uint8,
            'uint16':       self._read_uint16,
            'uint32':       self._read_uint32,
            'uint64':       self._read_uint64,
            'uint128':      self._read_uint128,
            'time':         self._read_time,
            'bool':         self._read_bool,
            'ipaddr-list':  self._read_ipaddr_list,
            'probe-list':   self._read_probe_list,
            'halting_list': self._read_halting_list
        }

        record_data = {}
        for c in record_format:
            record_data[c['name']] = fn[c['type']]()

        return record_data


if __name__ == '__main__':
    import sys

    if len(sys.argv) < 3:
        print('Too few arguments')
        exit()

    BinaryToJson(sys.argv[1], sys.argv[2])

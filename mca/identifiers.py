class Identifiers:

    def __init__(self, fields):
        self.fields = fields
        self.flow_ids_by_hop = {}
        self.flow_ids_by_hop_ip = {}
        self.values = {}

        # Initialize flow ids
        for f in fields:
            fids = [(x + 1) for x in range(255)]
            self.values[f] = fids

    def hop_has_flow_id(self, hop, flow_id):
        """
        Checks if a flow identifier was sent in a given hop
        """
        if hop not in self.flow_ids_by_hop:
            return False

        if flow_id not in self.flow_ids_by_hop[hop]:
            return False

        return self.flow_ids_by_hop[hop][flow_id]

    def save_flow_id(self, probe):
        """
        Saves a probe and keeps track of its flow identifier
        """

        ip = probe.answer_ip
        hop = probe.ttl
        flow_id = probe.flowid

        if hop not in self.flow_ids_by_hop:
            self.flow_ids_by_hop[hop] = {}
            self.flow_ids_by_hop_ip[hop] = {}

        if ip not in self.flow_ids_by_hop_ip[hop]:
            self.flow_ids_by_hop_ip[hop][ip] = {}

        if flow_id not in self.flow_ids_by_hop[hop]:
            self.flow_ids_by_hop[hop][flow_id] = probe
            self.flow_ids_by_hop_ip[hop][ip][flow_id] = probe

    def get_best_values(self, hop, ip, keeping_fields):
        flow_ids = list(self.flow_ids_by_hop_ip[hop][ip].keys())

        indexes = [self.fields.index(f) for f in keeping_fields]

        fields_tuples = []

        for f in flow_ids:
            t = tuple(f[i] for i in indexes)
            fields_tuples.append(t)

        best_tuple = max(set(fields_tuples), key=fields_tuples.count)

        return {keeping_fields[i]: best_tuple[i] for i in range(len(keeping_fields))}

    def get_discovery_flow_ids(self, hop, ip):
        if hop not in self.flow_ids_by_hop_ip:
            return []

        if ip not in self.flow_ids_by_hop_ip[hop]:
            return []

        unique_flow_ids = []
        flow_ids = list(self.flow_ids_by_hop_ip[hop][ip].keys())
        values = [set() for f in self.fields]

        for f in flow_ids:
            valid_flow_id = True
            for i in range(len(self.fields)):
                if f[i] in values[i]:
                    valid_flow_id = False
                    break

            if valid_flow_id:
                for i in range(len(self.fields)):
                    values[i].add(f[i])
                unique_flow_ids.append(f)

        return unique_flow_ids

    def create_new_discovery_flow_id(self, hop, ignore=[]):
        flow_ids = []
        if hop in self.flow_ids_by_hop:
            flow_ids = list(self.flow_ids_by_hop[hop].keys())

        values = [set() for f in self.fields]

        for f in flow_ids:
            for i in range(len(self.fields)):
                values[i].add(f[i])

        for f in ignore:
            for i in range(len(self.fields)):
                values[i].add(f[i])

        new_flow_id = []

        for i in range(len(self.fields)):
            available_value = False
            for v in self.values[self.fields[i]]:
                if v not in values[i]:
                    available_value = True
                    new_flow_id.append(v)
                    break

            if not available_value:
                return False

        return tuple(new_flow_id)

    def create_new_discovery_flow_ids(self, hop, n):
        flow_ids = set()

        while len(flow_ids) < n:

            f = self.create_new_discovery_flow_id(hop, flow_ids)

            if not f:
                break

            flow_ids.add(f)

        return list(flow_ids)

    def get_classify_flow_ids(self, hop, ip, varying_field):
        fields = set(self.fields)
        fields.remove(varying_field)
        keeping_fields = list(fields)

        best_values = self.get_best_values(hop, ip, keeping_fields)

        flow_ids = []

        for flow_id in self.flow_ids_by_hop_ip[hop][ip]:
            valid_flow_id = True
            for f in best_values:
                index = self.fields.index(f)
                if flow_id[index] != best_values[f]:
                    valid_flow_id = False
                    break

            if valid_flow_id:
                flow_ids.append(flow_id)

        return flow_ids

    def create_new_classify_flow_id(self, hop, varying_field, best_values, ignore={}):
        new_flow_id = [best_values[f] if f in best_values else 0 for f in self.fields]

        varying_field_index = self.fields.index(varying_field)

        for v in self.values[varying_field]:
            new_flow_id[varying_field_index] = v
            new_flow_id_tuple = tuple(new_flow_id)
            if new_flow_id_tuple not in self.flow_ids_by_hop[hop]:
                if new_flow_id_tuple not in ignore:
                    return new_flow_id_tuple

        return False

    def create_new_classify_flow_ids(self, hop, ip, varying_field, n):
        fields = set(self.fields)
        fields.remove(varying_field)
        keeping_fields = list(fields)

        best_values = self.get_best_values(hop, ip, keeping_fields)

        flow_ids = set()

        while len(flow_ids) < n:

            f = self.create_new_classify_flow_id(hop, varying_field, best_values, flow_ids)

            if not f:
                break

            flow_ids.add(f)

        return list(flow_ids)

    def flow_id_to_dict(self, flow_id):
        return {self.fields[i]: flow_id[i] for i in range(len(self.fields))}

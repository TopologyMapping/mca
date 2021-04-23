from collections import defaultdict
from collections.abc import Sequence
import dataclasses
from typing import Optional

from mca.probe import Probe


@dataclasses.dataclass
class Identifiers:
    fields: tuple[str]
    flow_ids_by_hop: dict[dict[Probe]] = dataclasses.field(default_factory=lambda: defaultdict(dict), init=False)
    flow_ids_by_hop_ip: dict[dict[dict[Probe]]] = dataclasses.field(default_factory=lambda: defaultdict(lambda: defaultdict(dict)), init=False)
    values: dict[list[int]] = dataclasses.field(init=False)

    extended_classification_flow_id_index_by_hop_and_ip: dict[dict[int]] = dataclasses.field(default_factory = lambda: defaultdict(lambda: defaultdict(lambda: 0)), init=False)

    def __post_init__(self):
        self.values = {field:list(range(1, 256)) for field in self.fields}


    def get_probe_for_hop_and_flow_id(self, ttl: int, flow_id: tuple[int]) -> Optional[Probe]:
        """
        Checks if a flow identifier was sent in a given hop,
        returning the probe object if True, None otherwise.

        Args:
            ttl (int): The ttl to check for the existence of the flow id
            flow_id (tuple[int]): The flow id being searched for

        Returns:
            Optional[Probe]: The probe for the given ttl and flow_id if it exists; None otherwise.

        """
        if ttl not in self.flow_ids_by_hop:
            return None

        if flow_id not in self.flow_ids_by_hop[ttl]:
            return None

        return self.flow_ids_by_hop[ttl][flow_id]

    def store_probe_result(self, probe: Probe) -> None:
        """
        Saves a probe and keeps track of its flow identifier.

        Args:
            probe (Probe): The probe to be saved.

        Returns:
            None
        """

        ip = probe.answer_ip
        hop = probe.ttl
        flow_id = probe.flowid

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

    def create_new_discovery_flow_id(self,
                                     hop: int,
                                     ignore: Sequence[tuple[int]] = ()) -> tuple[int]:
        """Create a new discovery flow ID.

        Creates a new flow ID that has not been sent before
        and is not in the list of flow IDs to ignore.

        Args:
            hop (int): hop for which a new flow ID will be created.
            ignore (Sequence[tuple[int]]): sequence of flow ids to ignore when
                creating the new flow ID.

        Returns:
            tuple[int]: the new flow ID, one int per field.

        Examples:
            This example assumes that 3 fields are being used:
            >>> create_new_discovery_flow_id(0, [(1,1,1), (2,2,2), (3,3,3)])
            (4,4,4)
        """

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

    def create_new_discovery_flow_ids(self, hop: int, n: int) -> list[tuple[int]]:
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

    def create_new_extended_classification_flow_id_index(self, ttl: int, ip: str) -> Optional[int]:
        """Create a new extended classification flow id index for a given ttl and ip.

        Creates a new extended classification flow id
        index for a given ttl and ip, an int index value
        for the high entropy flow id list.

        Args:
            hop (int): hop for which a new flow ID will be created.
            ip (str): ip of the interface for which a new flow ID will
                be created.

        Returns:
            Optional[int]: the new flow ID index if one is available;
                None otherwise.

        Examples:
            >>> create_new_extended_classification_flow_id_index(0, '8.8.4.4')
            0

        """
        value = self.extended_classification_flow_id_index_by_hop_and_ip[ttl][ip]
        if value > 255:
            return None
        self.extended_classification_flow_id_index_by_hop_and_ip[ttl][ip] += 1
        return value

from __future__ import annotations

from collections import defaultdict
import dataclasses
import logging
import hashlib
import random

import networkx as nx


NPROBES = [
    0,
    1,
    8,
    15,
    21,
    28,
    36,
    43,
    51,
    58,
    66,
    74,
    82,
    90,
    98,
    106,
    115,
    123,
    132,
    140,
    149,
    157,
    166,
    175,
    183,
    192,
    201,
    210,
    219,
    228,
    237,
    246,
    255,
    264,
    273,
    282,
    291,
    300,
    309,
    319,
    328,
    337,
    347,
    356,
    365,
    375,
    384,
    393,
    403,
    412,
    422,
    431,
    441,
    450,
    460,
    470,
    479,
]


def prob_src_target(graph, source, target) -> float:
    """Compute probability that probe from S reaches T in G."""
    prob = 0
    all_paths = nx.all_simple_paths(graph, source, target)
    for path in all_paths:
        degrees = g.out_degree(path[:-1])
        path_prob = 1
        for _node, out_degree in degrees:
            path_prob *= 1.0 / out_degree
        prob += path_prob
    return prob


@dataclasses.dataclass
class NodeDetectionStatus:
    needed: int
    known: int

    def __str__(self):
        return f"{self.probes_needed} needed of {self.probes_known} known"


@dataclasses.dataclass
class ProbeTip:
    radii: set[int] = dataclasses.field(default_factory=set)
    tip_node: str = None
    tip_radius: int = 0

    def update(self, nh, ttl):
        self.radii.add(ttl)
        if ttl > self.tip_radius:
            self.tip_node = nh
            self.tip_radius = ttl


@dataclasses.dataclass
class TopologyNode:
    discovered_ttl: int
    ttl2probes: dict[set[tuple[int]]] = dataclasses.field(
        default_factory=lambda: defaultdict(set)
    )
    classification_probes: dict = dataclasses.field(default_factory=dict)
    detection_probes_sent_next_hop: set[tuple[int]] = dataclasses.field(
        default_factory=set
    )
    classification_probes_sent_next_hop: set[tuple[int]] = dataclasses.field(
        default_factory=set
    )
    successors: set[str] = dataclasses.field(default_factory=set)
    classification: set = dataclasses.field(default_factory=set)
    hash_domain: set[str] = dataclasses.field(default_factory=set)
    enumerated_next_hops: bool = False

    def get_detection_status(self) -> NodeDetectionStatus:
        successors = len(self.successors)
        needed_probes = NPROBES[2] if successors == 0 else NPROBES[successors + 1]
        probes_sent = len(self.detection_probes_sent_next_hop)
        return NodeDetectionStatus(
            max(0, needed_probes - probes_sent),
            len(self.detection_probes_not_sent_next_hop()),
        )

    def detection_probes_not_sent_next_hop(self) -> set[tuple[int]]:
        """Computes set of probes that have been sent to n but not n's next hop"""
        discovered_ttl = self.discovered_ttl
        return self.ttl2probes[discovered_ttl] - self.detection_probes_sent_next_hop


class MCA:
    def __init__(self, src, dst, graph, hash_domains, fields, optimized):
        self.src = src
        self.dst = dst
        self.graph = graph
        self.hash_domains = hash_domains
        self.fields = fields
        self.optimized = optimized

        self.probing_cost = {
            "classification_node_control": 0,
            "classification": 0,
            "detection_node_control": 0,
            "detection": 0,
        }

        self.probe2tip = defaultdict(ProbeTip)
        self.ancestors = {}
        self.ancestor2node2prob = defaultdict(dict)
        self.ttl2probes = defaultdict(set)
        self.used_flow_ids = {}

        for f in fields:
            self.used_flow_ids[f] = set()

        self.topology = {src: TopologyNode(0)}
        self.discovered_hash_domains = {}

    def run(self) -> None:
        for ttl in range(0, 30 + 1):
            logging.info("ttl %d", ttl)
            self.detect_next_hops(ttl)
            for n in self.topology:
                # We classify a node on the first TTL it is discovered
                if self.topology[n].discovered_ttl != ttl:
                    continue
                if len(self.topology[n].successors) > 1:
                    self.classify_load_balancer(n, ttl)

    def detect_next_hops(self, ttl: int) -> None:
        logging.info("detect next hops @%d", ttl)
        node2detstatus = self.get_node_detection_status(ttl)
        while node2detstatus:
            self.detection_node_control(ttl)
            node2detstatus = self.get_node_detection_status(ttl)
            new_nodes = set()
            for node, detstatus in node2detstatus.items():
                total_sent = 0
                for probe in self.topology[node].detection_probes_not_sent_next_hop():
                    answer = self.send_probe(probe, ttl + 1)
                    self.probing_cost["detection"] += 1

                    self.topology[node].detection_probes_sent_next_hop.add(probe)
                    self.topology[node].successors.add(answer)
                    if answer not in self.topology:
                        self.topology[answer] = TopologyNode(ttl + 1)
                        new_nodes.add(answer)
                    self.topology[answer].ttl2probes[ttl + 1].add(probe)

                    total_sent += 1
                    if total_sent == detstatus.needed:
                        break

            logging.debug("new nodes @%d: %s", ttl, str(new_nodes))
            node2detstatus = self.get_node_detection_status(ttl)

    def detection_node_control(self, ttl: int) -> None:
        logging.debug("detection node control @%d", ttl)
        node2detstatus = self.get_node_detection_status(ttl)
        missing = sum(max(0, d.needed - d.known) for d in node2detstatus.values())
        while missing > 0:
            if self.optimized:
                probe = self.get_best_reusable_flow(ttl, node2detstatus)
                if probe is None:
                    probe = self.create_random_probe()
                    answer = self.send_probe(probe, ttl)
                else:
                    answer = self.send_probe(probe, ttl)
            else:
                probe = self.create_random_probe()
                answer = self.send_probe(probe, ttl)

            if ttl > 0:
                self.probing_cost["detection_node_control"] += 1

            if answer in self.topology:
                self.topology[answer].ttl2probes[ttl].add(probe)

            node2detstatus = self.get_node_detection_status(ttl)
            missing = sum(max(0, d.needed - d.known) for d in node2detstatus.values())

    def get_node_detection_status(self, ttl: int) -> dict[str, NodeDetectionStatus]:
        """Compute needed, known (set), and missing probes for each node at TTL"""
        node2detstatus = {}
        for n in [n for n, d in self.topology.items() if d.discovered_ttl == ttl]:
            if n == self.dst:
                continue
            detstatus = self.topology[n].get_detection_status()
            if detstatus.needed == 0:
                self.topology[n].enumerated_next_hops = True
            else:
                node2detstatus[n] = detstatus
        return node2detstatus

    def classify_load_balancer(self, n: str, h: int) -> None:
        logging.info("classifying %s@%d start", n, h)
        ancestor_fields = self.get_ancestor_hash_domain_fields(n)
        used_fields = set()
        for f in self.fields:
            answers = set()
            known_probes = self.topology[n].ttl2probes[h]
            known_probe = next(iter(known_probes))

            total_sent_probes = 0
            while total_sent_probes < NPROBES[2]:
                new_probe = list(tuple(known_probe))
                new_probe[self.fields.index(f)] = self.new_probe_field(f)
                new_probe = tuple(new_probe)

                if h == 0 or (self.optimized and f not in ancestor_fields):
                    # Skip node control
                    pass
                else:
                    node_control_answer = self.send_probe(new_probe, h)
                    self.probing_cost["classification_node_control"] += 1
                    if node_control_answer != n:
                        # Failed to reach target node, retry
                        continue

                answer = self.send_probe(new_probe, h + 1)
                total_sent_probes += 1
                self.probing_cost["classification"] += 1
                answers.add(answer)

                if len(answers) > 1:
                    used_fields.add(f)
                    break

        logging.info("classifying %s@%d -> %s", n, h, str(used_fields))
        self.topology[n].hash_domain = used_fields

    def get_ancestor_hash_domain_fields(self, n: str) -> set[str]:
        """Return set of fields used in ancestor hash domains"""
        ancestor_fields = set()
        for a in nx.ancestors(self.graph, n):
            # Ignore ancestors that are at a higher radii, probes will not traverse
            if a not in self.topology:
                continue
            assert len(self.topology[a].successors) == 1 or self.topology[a].hash_domain
            # Use ground truth self.hash_domains to avoid error propagation
            ancestor_fields.update(self.hash_domains.get(a, set()))
        return ancestor_fields

    def get_best_reusable_flow(self, ttl, node2detstatus) -> Optional[tuple[int]]:
        """Return optimal probe to send to ttl given detection statuses"""
        n2missing = {n: max(0, d.needed - d.known) for n, d in node2detstatus.items()}
        total_missing = sum(n2missing.values())

        best_probe = None
        best_utility = 0
        for node, missing in n2missing.items():
            m = missing / total_missing
            p = self.get_ancestor_node_prob(self.src, node)
            best_utility += m * p

        probe2utility = dict()
        for probe in self.reusable_flows(ttl):
            u = 0
            for node, missing in n2missing.items():
                m = missing / total_missing
                prob = self.probability_flow_reaches(probe, node)
                u += m * prob
            if u > best_utility:
                best_utility = u
                best_probe = probe
            probe2utility[probe] = u

        return best_probe

    def get_ancestor_node_prob(self, ancestor, node) -> float:
        "Get probability that probe from ancestor reaches node"
        if node not in self.ancestor2node2prob[ancestor]:
            self.ancestor2node2prob[ancestor][node] = prob_src_target(
                self.graph, ancestor, node
            )
        return self.ancestor2node2prob[ancestor][node]

    def probability_flow_reaches(self, probe, node) -> float:
        """Compute probability that probe reaches node from tip"""
        ancestor = self.probe2tip[probe].tip_node
        return self.get_ancestor_node_prob(ancestor, node)

    def reusable_flows(self, ttl) -> set[tuple[int]]:
        """Return set of probes that have not been sent to ttl"""
        return set(p for p, t in self.probe2tip.items() if ttl not in t.radii)

    def send_probe(self, probe, ttl) -> str:
        """Return node reached when sending probe to given TTL"""
        nh = self.src
        i = 0
        while i < ttl:
            if nh == self.dst:
                break
            suc = list(self.graph.successors(nh))
            if len(suc) == 1:
                nh = suc[0]
            else:
                ha = self.calculate_hash(probe, self.hash_domains[nh], nh)
                nh = suc[ha % len(suc)]
            i += 1
        self.ttl2probes[ttl].add(probe)
        self.probe2tip[probe].update(nh, ttl)
        logging.debug("probe @%d -> %s     %s", ttl, nh, probe)
        return nh

    def calculate_hash(self, probe, domain, ingress_link) -> int:
        """Compute hash for probe using fields in domain and ingress link"""
        flowid = "-".join(str(probe[self.fields.index(f)]) for f in sorted(domain))
        flowid += f"-{ingress_link}"
        return int(hashlib.md5(flowid.encode("utf-8")).hexdigest(), 16)

    def new_probe_field(self, field) -> int:
        """Create a new random value for using in a probe field"""
        v = random.randint(1, 9999999)
        while v in self.used_flow_ids[field]:
            v = random.randint(1, 9999999)
        self.used_flow_ids[field].add(v)
        return v

    def create_random_probe(self) -> tuple[int]:
        """Generate a probe tuple with one value for each field"""
        return tuple([self.new_probe_field(f) for f in self.fields])


if __name__ == "__main__":
    logging.basicConfig(
        filename="simulation.log", level=logging.INFO, format="%(message)s"
    )

    g = nx.DiGraph()
    g.add_edge("s", "a1")
    g.add_edge("s", "a2")
    g.add_edge("a1", "b1")
    g.add_edge("a1", "b2")
    g.add_edge("a2", "b2")
    g.add_edge("b1", "c1")
    g.add_edge("b1", "c2")
    g.add_edge("c1", "d")
    g.add_edge("c2", "d")
    g.add_edge("b2", "d")

    hash_domains = {
        "s": ["daddr", "dport"],
        "a1": ["daddr", "dport", "fl"],
        "b1": ["fl"],
    }

    fields = ["daddr", "dport", "fl"]

    mca = MCA("s", "d", g, hash_domains, fields, optimized=True)
    mca.run()
    # These assertions have a small probability of failing as MDA and MCA
    # are probabilistic algorithms. If the asserts fail, try running the
    # simulator again. We keep the assertions here for documentation and
    # catching bugs.
    assert mca.topology["s"].hash_domain == set(["daddr", "dport"])
    assert mca.topology["a1"].hash_domain == set(["daddr", "dport", "fl"])
    assert mca.topology["b1"].hash_domain == set(["fl"])
    assert mca.topology["s"].successors == set(["a1", "a2"])
    assert mca.topology["a1"].successors == set(["b1", "b2"])
    assert mca.topology["b1"].successors == set(["c1", "c2"])
    assert mca.topology["c1"].successors == set(["d"])
    print(mca.probing_cost)

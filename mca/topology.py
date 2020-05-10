class Node:

    def __init__(self, ip):
        self.ip = ip
        self.parents = []
        self.next_hops = []
        self.halt = False
        self.halt_cause = None
        self.explored_next_hops = False
        self.per_packet_traffic = False
        self.mca_node = False

    def add_parent(self, node):
        if node not in self.parents:
            self.parents.append(node)

    def add_next_hop(self, node):
        if node not in self.next_hops:
            self.next_hops.append(node)


class Topology:

    def __init__(self):
        self.nodes = {}
        self.topology = {}

    def find_node(self, ip):
        if ip not in self.nodes:
            return False

        return self.nodes[ip]

    def add_node(self, ttl, ip, topology=True):
        n = self.find_node(ip)

        if not n:
            n = Node(ip)
            self.nodes[ip] = n

        if topology:
            if ttl not in self.topology:
                self.topology[ttl] = []
            if n not in self.topology[ttl]:
                self.topology[ttl].append(n)

        return n

    def get_nodes_ttl(self, ttl, check_mca=False):
        if ttl not in self.topology:
            return []

        nodes = []
        for n in self.topology[ttl]:
            if not check_mca or n.mca_node:
                nodes.append(n)

        return nodes

    def check_gap_limit(self, node, gap_limit):
        if '*' not in node.ip:
            return False

        if gap_limit == 1:
            return True if '*' in node.ip else False

        if len(node.parents) > 1:
            return False

        return self.check_gap_limit(node.parents[0], gap_limit - 1)

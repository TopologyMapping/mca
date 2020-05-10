import argparse
import os
import sys

import mca.mca

def __create_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        'dst_ip',
        type=str,
        help='Host IPv4/v6 address to trace to',
    )
    parser.add_argument(
        '--max-ttl',
        type=int,
        default=30,
        help='Set the max number of hops. Default is 30',
    )
    parser.add_argument(
        '--alpha',
        type=int,
        default=95,
        help='Level of confidence for MCA, one of 90, 95, 99. Default is 95',
    )
    parser.add_argument(
        '--max-nh',
        type=int,
        default=16,
        help='Max number of successors for a node in the graph. Default is 16',
    )
    parser.add_argument(
        '--max-border',
        type=int,
        default=16,
        help='Max number of leaves in the graph at any time. Default is 16',
    )
    parser.add_argument(
        '--gap-limit',
        type=int,
        default=3,
        help='Max number of consecutive unhesponsive hops. Default is 3',
    )
    parser.add_argument(
        '--fields',
        type=str,
        default=['dport'],
        nargs='+',
        help='Header fields to use for load balancing detection/classification',
    )
    parser.add_argument(
        '--max-attempts',
        type=int,
        default=2,
        help='Max number of attempts before discarding a probe. Default is 2',
    )
    parser.add_argument(
        '--wait-timeout',
        type=int,
        default=1,
        help='Max time (in seconds) to wait for an answer. Default is 1',
    )
    parser.add_argument(
        '--probe-type',
        type=str,
        default='udp',
        help='Set the probe type. Can be icmp, tcp, udp. Default is udp',
    )
    parser.add_argument(
        '--pps',
        type=int,
        default=50,
        help='Max number of packets to send per second',
    )
    parser.add_argument(
        '--instance-id',
        type=int,
        default=1,
        help='MCA running instance identifier',
    )
    parser.add_argument(
        '--record-file',
        type=str,
        default='',
        help='Name of the file to write detailed measurement results',
    )
    return parser

def main():
    if not os.geteuid() == 0:
        sys.stdout.write("mca-traceroute requires root privileges.\n")
        sys.exit(1)

    parser = __create_parser()
    args = parser.parse_args()
    g = mca.mca.MCA(args.dst_ip, args.max_ttl, args.alpha, args.max_nh,
            args.max_border, args.gap_limit, args.fields, args.max_attempts,
            args.wait_timeout, args.probe_type, args.pps, args.instance_id)

    if args.record_file != '':
        g.record_data.dump(args.record_file)

if __name__ == '__main__':
    sys.exit(main())

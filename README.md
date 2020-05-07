# MCA

This tool implements the algorithm described in the paper
Classification of Load Balancing in the Internet (INFOCOM 2020).

## Dependencies

```
python 3.6.9
scapy 2.4.3
```

### Usage

```
usage: mca.py [-h] [--max-ttl MAX_TTL] [--alpha ALPHA] [--max-nh MAX_NH]
              [--max-border MAX_BORDER] [--gap-limit GAP_LIMIT]
              [--fields FIELDS [FIELDS ...]] [--max-attempts MAX_ATTEMPTS]
              [--wait-timeout WAIT_TIMEOUT] [--probe-type PROBE_TYPE]
              [--pps PPS] [--instance-id INSTANCE_ID]
              [--record-file RECORD_FILE]
              dst_ip

positional arguments:
  dst_ip                Host IPv4/v6 address to trace to

optional arguments:
  -h, --help            show this help message and exit
  --max-ttl MAX_TTL     Set the max number of hops. Default is 30
  --alpha ALPHA         Level of confidence for MCA, one of 90, 95, 99.
                        Default is 95
  --max-nh MAX_NH       Max number of successors for a node in the graph.
                        Default is 16
  --max-border MAX_BORDER
                        Max number of leaves in the graph at any time. Default
                        is 16
  --gap-limit GAP_LIMIT
                        Max number of consecutive unhesponsive hops. Default
                        is 3
  --fields FIELDS [FIELDS ...]
                        Header fields to use for load balancing
                        detection/classification
  --max-attempts MAX_ATTEMPTS
                        Max number of attempts before discarding a probe.
                        Default is 2
  --wait-timeout WAIT_TIMEOUT
                        Max time (in seconds) to wait for an answer. Default
                        is 1
  --probe-type PROBE_TYPE
                        Set the probe type. Can be icmp, tcp, udp. Default is
                        udp
  --pps PPS             Max number of packets to send per second
  --instance-id INSTANCE_ID
                        MCA running instance identifier
  --record-file RECORD_FILE
                        Name of the file to write detailed measurement results
```

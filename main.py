import argparse
import sys
import logging
import re
from pythonjsonlogger import jsonlogger
import sqlparse
from scapy.all import *
from kubernetes import client, config, watch
import threading
import time
from readerwriterlock import rwlock

lock = rwlock.RWLockWrite()

config.load_incluster_config()
v1 = client.CoreV1Api()
apps_v1 = client.AppsV1Api()
w = watch.Watch()

nodes_by_ip = dict()
pods_by_ip = dict()
replica_sets = dict()


def watch_node():
    for event in w.stream(v1.list_node, timeout_seconds=60):
        event_type = event["type"]
        event_object = event["object"]
        node_internal_ip_addresses = list(filter(
            lambda address: address.type == "InternalIP", event_object.status.addresses))
        if (event_type == "ADDED" or event_type == "MODIFIED") and len(node_internal_ip_addresses) > 0:
            with lock.gen_wlock():
                nodes_by_ip[node_internal_ip_addresses[0].address] = event_object
        if event_type == "DELETED" and len(node_internal_ip_addresses) > 0:
            with lock.gen_wlock():
                del nodes_by_ip[node_internal_ip_addresses[0].address]


def watch_pod():
    for event in w.stream(v1.list_pod_for_all_namespaces, timeout_seconds=60):
        event_type = event["type"]
        event_object = event["object"]
        if (event_type == "ADDED" or event_type == "MODIFIED") and event_object.status.pod_ip and not event_object.spec.host_network:
            with lock.gen_wlock():
                pods_by_ip[event_object.status.pod_ip] = event_object
        if event_type == "DELETED" and event_object.status.pod_ip:
            with lock.gen_wlock():
                del pods_by_ip[event_object.status.pod_ip]


def watch_replica_set():
    for event in w.stream(apps_v1.list_replica_set_for_all_namespaces, timeout_seconds=60):
        event_type = event["type"]
        event_object = event["object"]
        if event_type == "ADDED" or event_type == "MODIFIED":
            with lock.gen_wlock():
                replica_sets[event_object.metadata.name] = event_object
        if event_type == "DELETED":
            with lock.gen_wlock():
                del replica_sets[event_object.metadata.name]


def get_caller_details(ip):
    caller_details = {
        "caller_type": "unknown",
        "caller_name": "unknown",
        "caller_namespace": "unknown",
        "caller_ip": ip
    }

    if ip in pods_by_ip:
        pod = pods_by_ip[ip]
        caller_details["caller_type"] = "pod"
        caller_details["caller_name"] = pod.metadata.name
        caller_details["caller_namespace"] = pod.metadata.namespace
        caller_details["caller_details"] = {}
        caller_details["caller_details"]["pod"] = {"name": pod.metadata.name}
        caller_details["caller_details"]["node"] = {
            "name": pod.spec.node_name, "ip": pod.status.host_ip}

        if len(pod.metadata.owner_references) > 0:
            owner_reference = pod.metadata.owner_references[0]
            caller_details["caller_type"] = owner_reference.kind.lower()
            caller_details["caller_name"] = owner_reference.name
            caller_details["caller_details"][owner_reference.kind.lower()] = {
                "name": owner_reference.name}

            if owner_reference.kind == "ReplicaSet" and owner_reference.name in replica_sets:
                replica_set = replica_sets[owner_reference.name]
                if len(replica_set.metadata.owner_references) > 0:
                    owner_reference = replica_set.metadata.owner_references[0]
                    caller_details["caller_type"] = owner_reference.kind.lower()
                    caller_details["caller_name"] = owner_reference.name
                    caller_details["caller_details"][owner_reference.kind.lower()] = {
                        "name": owner_reference.name}

    elif ip in nodes_by_ip:
        node = nodes_by_ip[ip]
        caller_details["caller_type"] = "node"
        caller_details["caller_name"] = node.metadata.name
        caller_details["caller_details"] = {}
        caller_details["caller_details"]["node"] = {
            "name": node.metadata.name, "ip": ip}

    return caller_details


# Set Scapy's TCP reassembly limit to unlimited
conf.contribs['TCPSession'] = {'reassembler': 'nosack'}

queries = ['select', 'insert', 'update', 'delete', 'call']

query = dict()
user = dict()


def parse_mysql_packet(packet, port):
    if packet.haslayer(TCP) and packet.haslayer(Raw) and packet[TCP].dport == port:
        payload = bytes(packet[Raw].load)

        if len(payload) <= 4:
            logger.info("skip packet len < 4", extra={"packet": payload})

        global query, user

        if payload[4] == 0x03:
            query[port] = payload[5:]
        else:
            match_user = re.search(rb'\x00(\w+)\x00', payload)
            if match_user:
                user[port] = match_user.group(1).decode()

        try:
            data = query[port].decode('utf-8')
        except UnicodeDecodeError:
            try:
                data = query[port].decode('latin1')
            except UnicodeDecodeError:
                # If both decodings fail, log the error and return
                logger.error("Failed to decode query")
                return

        words = data.strip().split()
        if words and words[0].lower() in queries:
            source_ip = packet[IP].src
            with lock.gen_rlock():
                caller_details = get_caller_details(source_ip)
            sql = sqlparse.format(data, output_format="sql", keyword_case="upper",
                                  strip_whitespace=True, use_space_around_operators=True).replace(",", ", ")
            logger.info(
                sql, extra={"port": port, "caller_username": user[port], **caller_details})


def sniff_mysql_packets(port):
    tcp_session = TCPSession()
    sniff(filter=f"tcp port {port} and tcp[13] == 24", prn=lambda packet: parse_mysql_packet(
        packet, port), session=tcp_session)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='MySQL packet sniffer')
    parser.add_argument('-p', '--port', type=str,
                        help='MySQL server port', default="3306")
    parser.add_argument('-v', '--version', action='version', version='0.0.5')
    args = parser.parse_args()

    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    logHandler = logging.StreamHandler()
    jsonlogger.RESERVED_ATTRS = (*jsonlogger.RESERVED_ATTRS, "taskName")
    formatter = jsonlogger.JsonFormatter(timestamp=True)
    logHandler.setFormatter(formatter)
    logger.addHandler(logHandler)

    threading.Thread(target=watch_node, daemon=True).start()
    threading.Thread(target=watch_pod, daemon=True).start()
    threading.Thread(target=watch_replica_set, daemon=True).start()

    logger.info("loading kubernetes resource...")
    while True:
        time.sleep(5)
        if len(nodes_by_ip) > 0 and len(pods_by_ip) > 0 and len(replica_sets) > 0:
            time.sleep(15)
            logger.info("kubernetes resource loaded")
            break

    try:
        for port in map(lambda port: int(port), args.port.split(",")):
            query[port] = b""
            user[port] = "unknown"
            threading.Thread(target=sniff_mysql_packets,
                             args=(port,), daemon=True).start()
        logger.info("sniffing operation started")
        while True:
            pass
    except KeyboardInterrupt:
        logger.info("sniffing operation stopped")
        sys.exit(0)

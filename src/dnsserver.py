from __future__ import annotations
import json
import socket
import time
from dnslib import A, QTYPE, RR, DNSRecord


DNS_SERVERS = ["198.41.0.4", "170.247.170.2", "192.33.4.12", "199.7.91.13", "192.203.230.10", "192.5.5.241", "192.112.36.4", "198.97.190.53",
               "192.36.148.17", "192.58.128.30", "193.0.14.129", "199.7.83.42", "202.12.27.33"]

host = '127.0.0.1'
cache = {}
socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
socket.bind((host, 53))
dns_query_type = None


def DNS_server():
    while True:
        data, addr = socket.recvfrom(512)
        dns_record = DNSRecord.parse(data)
        q_name = dns_record.q.qname.__str__()
        if dns_record.q.qtype != 1:
            socket.sendto(data, addr)
        elif 'multiply' in q_name:
            socket.sendto(recieve_response(dns_record), addr)
        else:
            if q_name in cache:
                reply = get_records_from_cache(dns_record, q_name)
                if reply.a.rdata:
                    socket.sendto(reply.pack(), addr)
                    continue
                else:
                    del cache[q_name]
            result = None
            for root_server in DNS_SERVERS:
                dns_query_type = dns_record.q.qtype
                result = lookup_util(dns_record, root_server)
                if result:
                    break
            save_in_cache(q_name, DNSRecord.parse(result))
            socket.sendto(result, addr)


def get_records_from_cache(dns_record: DNSRecord, q_name: str):
    reply = dns_record.reply()
    current_time = time.time()
    for answer in cache[q_name]:
        if answer[2] + answer[1] - current_time >= 0:
            rr = RR(rname=q_name, rtype=QTYPE.A,
                    rdata=A(answer[0]), ttl=answer[1])
            reply.add_answer(rr)
    return reply


def save_in_cache(request: str, result: DNSRecord):
    answers = []
    for rr in result.rr:
        answers.append((rr.rdata.__str__(), rr.ttl, time.time()))
    if len(answers) == 0:
        return
    cache[request] = answers
    update_cache()


def update_cache():
    with open('cache.json', 'w') as cash:
        json.dump(cache, cash)


def load_cache():
    try:
        with open('cache.json', 'r') as cash:
            data = json.load(cash)
            if data:
                global cache
                cache = data
    except FileNotFoundError:
        update_cache()


def lookup_util(dns_record: DNSRecord, zone_ip: str):
    response = dns_record.send(zone_ip)
    parsed_response = DNSRecord.parse(response)
    for adr in parsed_response.auth:
        if adr.rtype == 6:
            return response
    if parsed_response.a.rdata:
        return response
    new_zones_ip = get_new_zones_ip(parsed_response)
    for new_zone_ip in new_zones_ip:
        ip = lookup_util(dns_record, new_zone_ip)
        if ip:
            return ip
    return None


def get_new_zones_ip(parsed_response: DNSRecord):
    new_zones_ip = []
    for adr in parsed_response.ar:
        if adr.rtype == 1:
            new_zones_ip.append(adr.rdata.__repr__())
    if len(new_zones_ip) == 0:
        for adr in parsed_response.auth:
            if adr.rtype == 2:
                question = DNSRecord.question(adr.rdata.__repr__())
                pkt = lookup_util(question, DNS_SERVERS[0])
                parsed_pkt = DNSRecord.parse(pkt)
                new_zone_ip = parsed_pkt.a.rdata.__repr__()
                if new_zone_ip:
                    new_zones_ip.append(new_zone_ip)
    return new_zones_ip


def recieve_response(dns_record: DNSRecord):
    name = dns_record.q.qname.__str__()
    index = name.find('multiply')
    zones = name[:index].split('.')
    sch = 0
    for zone in zones:
        try:
            number = int(zone)
            if sch == 0:
                sch = 1
            sch *= number
        except ValueError:
            continue
    sch %= 256
    reply_ip = f'127.0.0.{sch}'
    reply = dns_record.reply()
    reply.add_answer(RR(dns_record.q.qname, QTYPE.A,
                        rdata=A(reply_ip), ttl=60))
    return reply.pack()


load_cache()
DNS_server()
#запуск через терминал: py dnsserver.py
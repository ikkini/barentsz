#!/usr/bin/env python

##!/opt/local/bin/python2.7
# The line above is macOS specific (YMMV). 
# Replace it with the line below if you have the right python as an environmental setting: 
##!/usr/bin/env python

# This tool scratches a very particular itch in a very personal way: host discovery done My Way.
# YMMV
# To view results, do something like: sqlite3 --header <PREFIX>__barentsz.db ' select * from ips where alive = 1;'

# development timer option
#class Timer():
#    def __enter__(self): self.start = time.time()
#    def __exit__(self, *args): print time.time() - self.start

# check for root access (we are going to abuse network interfaces, you'l need it)
import os,sys
if os.geteuid() != 0:
    print "sorry, you need to run this as root"
    exit(1)

# XXX will have to change to only be a source of payloads
import cb

if cb.UNREAD:
    print """cb.py is where you configure your targets and settings.
             Please have a look at that file first"""
    exit(1)

# import necessary default libraries
import sys, socket, struct, zlib, warnings, time, random

# supress IPV6 WARNING at startup
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# needed for logging
from datetime import datetime

# libraries not available by default
try:
    from scapy.all import *
except:
    print "install scapy"
    print "http://www.secdev.org/projects/scapy/"
    exit(1)
try:
    from netaddr import *
except:
    print "install netaddr"
    print "http://pypi.python.org/pypi/netaddr"
    exit(1)

try:
    import sqlite3 as lite
except:
    print "install sqlite3"
    print "http://www.sqlite.org/"
    exit(1)

# command line options 
from optparse import OptionParser
#
parser = OptionParser()

# prefix
parser.add_option('-p', '--prefix',
                    action="store",
                    default=False,
                    dest="PREFIX",
		    type="string",
                    help='Prefix for the log + database files, default none')

# continue
parser.add_option('-c', '--continue',
                    action="store_true",
                    dest="CONTINUE",
                    default=False,
                    help='continue with the previous logs/database')

# interface selection
parser.add_option("-I", "--interface",
                    action="store",
                    dest="IFACE",
                    default=False,
                    help="interface name, like eth0 or en1, not normally required, currently " + conf.iface,
                    type="string")

# scantypes
parser.add_option('-i', '--icmp',
                    action="store_true",
                    dest="ICMP",
                    default=False,
                    help='Run ICMP checks')

parser.add_option('-u', '--udp',
                    action="store_true",
                    dest="UDP",
                    default=False,
                    help='Run UDP checks')

parser.add_option('-t', '--tcp',
                    action="store_true",
                    dest="TCP",
                    default=False,
                    help='Run TCP checks')

parser.add_option('-d', '--dns',
                    action="store_true",
                    dest="DNS",
                    default=False,
                    help='Run dns check')

parser.add_option('-k', '--ike',
                    action="store_true",
                    dest="IKE",
                    default=False,
                    help='Run ISAKMP checks')

parser.add_option('-s', '--snmp',
                    action="store_true",
                    dest="SNMP",
                    default=False,
                    help='Run SNMP checks')

# option parsing
(options, args) = parser.parse_args()

# check for prefix
if options.PREFIX:
    PREFIX = str(options.PREFIX)
else:
    PREFIX = ''

# Open database, support resuming scans
try:
   open(PREFIX + "_barentsz.db")
except IOError as e:
    print 'Starting with a new database'
    pass
else:
    if options.CONTINUE:
       pass
    else:
       print "database % already exists." % (PREFIX + "_barentsz.db")
       print 'please use "-c" or "--continue" if you want to continue using a previous database'
       exit(1)

# check for interface option
if options.IFACE:
    conf.iface = options.IFACE

# set option selection
if options.ICMP or options.UDP or options.TCP or options.DNS or options.IKE or options.SNMP:
    options.ALL = False
else:
    options.ALL = True

# XXX there must be a better way to find our local IP?
cb.scannerip = [x[4] for x in scapy.all.conf.route.routes if x[2] != '0.0.0.0'][0]

# get the batchsize
concurrent = cb.concurrent

# define the pcap file
pcapfile = PREFIX + "_barentsz.pcap"

# We want a start time for our log
starttime = str(datetime.now())

# Only test IP if not found live yet, do so in batches
def itsAlive(max,start):
    T = []
    cur.execute('SELECT ip from ips where alive=0 limit ?,?', (max,start))
    rows = cur.fetchall()
    for row in rows:
        T.append(row['ip'])
    return T

# create/ connect to database
database = PREFIX + '_barentsz.db'
con = lite.connect(database)
with con:
    cur = con.cursor()

    # ips should be unique
    cur.execute("CREATE TABLE ips(ip STRING UNIQUE, alive BOOLEAN default 0, info STRING, ttl INT, type STRING, iperror INT default 0, seen INT default 0)")
    # XXX with Timer():
    # if cb.targets_iter exists, it takes precendence
    if cb.targets_iter:
        cb.targets = list(iter_iprange(cb.targets_iter[0], cb.targets_iter[1]))

    for target in cb.targets:
        IPs = []
        for ip in IPNetwork(target):
            item =  str(ip)
            cur.execute('INSERT OR IGNORE INTO ips (ip) VALUES (?)', [item])
    cur.execute('SELECT count(ip) from ips')

    # get total number of rows in a table
    total = cur.fetchall()[0][0]
print "You are going to scan %s IP addresses" % (total)

# ICMP, run through number of types
if options.ICMP or options.ALL:
    counter = 0
    while counter < total:
        for ICMPtype in cb.ICMPtypes:
            with con:
                con.row_factory = lite.Row
                cur = con.cursor()
                TARGETS = itsAlive(counter,concurrent)
                if len(TARGETS) == 0:
                    break
                else:
                    print "ICMPtype: %s" % (str(ICMPtype))
                    ans,unans=sr(IP(dst=TARGETS)/ICMP(type=ICMPtype),inter=cb.inter,retry=cb.retry,timeout=cb.timeout)
                writer = PcapWriter(pcapfile, append=True)
                for answer in ans:
                    writer.write(answer)
                    for l in answer:
                        if l.haslayer(IPerror) and l[IP].src != cb.scannerip:
                            cur.execute('UPDATE ips SET alive=?,type=?,info=?,ttl=?,iperror=?,seen=? WHERE ip = ?', [1,'ICMP','type:' + str(ICMPtype) + 'errorip:' + l[IP].src,l[IP].ttl,1,1,l[IPerror].dst])
                        elif l[IP].src != cb.scannerip:
                            cur.execute('UPDATE ips SET alive=?,type=?,info=?,ttl=?,iperror=?,seen= seen + ? WHERE ip = ?', [1,'ICMP','type:' + str(ICMPtype), l[IP].ttl,0,1,l[IP].src])
                writer.close()
        counter += concurrent

##UDP, hoping for ICMP answers
if options.UDP or options.ALL:
    counter = 0
    while counter < total:
        for UDPport in cb.UDPports:
            with con:
                con.row_factory = lite.Row
                cur = con.cursor()
                TARGETS = itsAlive(counter,concurrent)
                if len(TARGETS) == 0:
                    break
                else:
                    print "UDPport: %s" % (str(UDPport))
                    ans,unans=sr(IP(dst=TARGETS)/UDP(dport=UDPport),inter=cb.inter,retry=cb.retry,timeout=cb.timeout)
                writer = PcapWriter(pcapfile, append=True)
                for answer in ans:
                    writer.write(answer)
                    for l in answer:
                        if l.haslayer(IPerror) and l[IP].src != cb.scannerip:
                            cur.execute('UPDATE ips SET alive=?,type=?,info=?,ttl=?,iperror=?,seen=? WHERE ip = ?', [1,'UDP','dport:' + str(UDPport) + 'errorip:' + l[IP].src,l[IP].ttl,1,1,l[IPerror].dst])
                        elif l[IP].src != cb.scannerip:
                            cur.execute('UPDATE ips SET alive=?,type=?,info=?,ttl=?,iperror=?,seen=? WHERE ip = ?', [1,'UDP','dport:'+ str(UDPport),l[IP].ttl,0,1,l[IP].src])
                writer.close()
        counter += concurrent

##TCP, Syn scan from port cb.tcpsourceport 
if options.TCP or options.ALL:
    counter = 0
    while counter < total:
        for TCPport in cb.TCPports[:cb.toptcpports]:
            with con:
                con.row_factory = lite.Row
                cur = con.cursor()
                TARGETS = itsAlive(counter,concurrent)
                if len(TARGETS) == 0:
                    break
                else:
                    print "TCPport: %s" % (str(TCPport))
                    ans,unans=sr(IP(dst=TARGETS)/TCP(sport=cb.tcpsourceport,dport=TCPport),inter=cb.inter,retry=cb.retry,timeout=cb.timeout)
                writer = PcapWriter(pcapfile, append=True)
                for answer in ans:
                    writer.write(answer)
                    for l in answer:
                        if l.haslayer(IPerror) and l[IP].src != cb.scannerip:
                            cur.execute('UPDATE ips SET alive=?,type=?,info=?,ttl=?,iperror=?,seen=? WHERE ip = ?', [1,'TCP','dport:' + str(TCPport) + 'errorip:' + l[IP].src,l[IP].ttl,1,1,l[IPerror].dst])
                        elif l[IP].src != cb.scannerip:
                            cur.execute('UPDATE ips SET alive=?,type=?,info=?,ttl=?,iperror=?,seen=? WHERE ip = ?', [1,'TCP','dport:'+ str(TCPport),l[IP].ttl,0,1,l[IP].src])
                writer.close()
        counter += concurrent

## DNS query (for 127.0.0.1)
if options.DNS or options.ALL:
    counter = 0
    while counter < total:
        with con:
            con.row_factory = lite.Row
            cur = con.cursor()
            TARGETS = itsAlive(counter,concurrent)
            if len(TARGETS) == 0:
                break
            else:
                print "DNS query: %s" % ('127.0.0.1',)
                ans,unans=sr(IP(dst=TARGETS)/UDP(sport=53,dport=53)/DNS(rd=1,qd=DNSQR(qname='localhost')),inter=cb.inter,retry=cb.retry,timeout=cb.timeout)
            writer = PcapWriter(pcapfile, append=True)
            for answer in ans:
                writer.write(answer)
                for l in answer:
                    if l.haslayer(IPerror) and l[IP].src != cb.scannerip:
                        cur.execute('UPDATE ips SET alive=?,type=?,info=?,ttl=?,iperror=?,seen=? WHERE ip = ?', [1,'DNS','errorip:' + l[IP].src,l[IP].ttl,1,1,l[IPerror].dst])
                    elif l[IP].src != cb.scannerip:
                        cur.execute('UPDATE ips SET alive=?,type=?,info=?,ttl=?,iperror=?,seen=? WHERE ip = ?', [1,'DNS','rcode:' + l[DNS].rcode,l[IP].ttl,0,1,l[IP].src])
            writer.close()
        counter += concurrent

# ikescan copy, simple default without generate-transforms.sh
if options.IKE or options.ALL:
    counter = 0
    while counter < total:
        for ISAKMPport in cb.ISAKMPports:
            for transform in cb.ISAKMPtransforms:
                with con:
                    con.row_factory = lite.Row
                    cur = con.cursor()
                    TARGETS = itsAlive(counter,concurrent)
                    if len(TARGETS) == 0:
                        break
                    else:
                        print "ISAKMP: %s" % (str(ISAKMPport))
                        ans,unans=sr(IP(proto='udp',dst=TARGETS)/UDP(sport=ISAKMPport,dport=ISAKMPport)/ISAKMP(init_cookie=(RandString(8)),next_payload='SA',exch_type='identity prot.')/ISAKMP_payload_SA(prop=ISAKMP_payload_Proposal(trans_nb=1,trans=ISAKMP_payload_Transform(next_payload=None,num=2,transforms=transform))),inter=cb.inter,retry=cb.retry,timeout=cb.timeout)
                    writer = PcapWriter(pcapfile, append=True)
                    for answer in ans:
                        writer.write(answer)
                        for l in answer:
                            if l.haslayer(IPerror) and l[IP].src != cb.scannerip:
                                cur.execute('UPDATE ips SET alive=?,type=?,info=?,ttl=?,iperror=?,seen=? WHERE ip = ?', [1,'IKE','dport:' + str(ISAKMPport) + 'errorip:' + l[IP].src,l[IP].ttl,1,1,l[IPerror].dst])
                            elif l[IP].src != cb.scannerip:
                                cur.execute('UPDATE ips SET alive=?,type=?,info=?,ttl=?,iperror=?,seen=? WHERE ip = ?', [1,'IKE','dport:' + str(ISAKMPport),l[IP].ttl,0,1,l[IP].src])
                    writer.close()
        counter += concurrent

## SNMP community brute force scan
if options.SNMP or options.ALL:
    counter = 0
    while counter < total:
        for SNMPcommunity in cb.SNMPcommunities:
            with con:
                con.row_factory = lite.Row
                cur = con.cursor()
                TARGETS = itsAlive(counter,concurrent)
                if len(TARGETS) == 0:
                    break
                else:
                    print "community: %s" % (SNMPcommunity)
                    ans,unans=sr(IP(dst=TARGETS)/UDP(sport=161,dport=161)/SNMP(community=SNMPcommunity,PDU=SNMPget(varbindlist=[SNMPvarbind(oid=ASN1_OID("1.3.6.1.2.1.1.1.0"))])),inter=0.3,retry=0,timeout=1)
                writer = PcapWriter(pcapfile, append=True)
                for answer in ans:
                    writer.write(answer)
                    for l in answer:
                        if l.haslayer(IPerror) and l[IP].src != cb.scannerip:
                            cur.execute('UPDATE ips SET alive=?,type=?,info=?,ttl=?,iperror=?,seen=? WHERE ip = ?', [1,'SNMP','comm:' + str(SNMPcommunity) + 'errorip:' + l[IP].src,l[IP].ttl,1,1,l[IPerror].dst])
                        elif l[IP].src != cb.scannerip:
                            cur.execute('UPDATE ips SET alive=?,type=?,info=?,ttl=?,iperror=?,seen=? WHERE ip = ?', [1,'SNMP','community:' + str(SNMPcommunity),l[IP].ttl,0,1,l[IP.src]])
                writer.close()
        counter += concurrent
# Automate logging our scan.
with open(PREFIX + "_barentsz.log", 'a') as log:
    log.write("--- ")
    log.write("started: " + starttime)
    log.write("\nended: " + str(datetime.now()))
    log.write("\ninter: " + str(cb.inter) + "\nretry: " + str(cb.retry) + "\ntimeout: " + str(cb.timeout) + "\nconcurrent: " + str(concurrent))

    if options.ICMP or options.ALL:
        log.write("\nICMPtypes: " + ",".join(str(x) for x in cb.ICMPtypes))
    if options.UDP or options.ALL:
        log.write("\nUDPports: " + ",".join(str(x) for x in cb.UDPports))
    if options.TCP or options.ALL:
        log.write("\ntoptcpports: " + str(cb.toptcpports) + "\nTCPports: " +  ",".join(str(x) for x in cb.TCPports[:cb.toptcpports]))
    if options.SNMP or options.ALL:
        log.write("\nSNMPcommunities: " + ",".join(str(x) for x in cb.SNMPcommunities))
    if options.IKE or options.ALL:
        log.write("\nISAKMPports: " + ",".join(str(x) for x in cb.ISAKMPports))
    log.write("\n")

print  "To view results, do something like: sqlite3 --header " + PREFIX + "_barentsz.db ' select * from ips where alive = 1;'"

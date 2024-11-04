#!/usr/bin/python3

from scapy.all import *
from scapy.layers import http
import argparse

incident_number = 0


def packetcallback(packet):

  global incident_number
  
  try:

    # see if usernames and passwords sent in-the-clear via HTTP Basic 
    # Authentication
    if packet[TCP].dport == 80:
        # check for usernames and passwords sent in-the-clear 
        req = packet.getlayer('HTTP Request')

        if req:
            auth = req.Authorization
        
            if auth:
                if auth.startswith(b'Basic '):
  
                    incident_number += 1
                    username, password = base64_bytes(auth.split(None, 1)[1]).split(b':', 1)
                    print("ALERT # %r: Usernames and passwords sent in-the-clear (HTTP) (username: %r, password: %r)" % (incident_number, username.decode(), password.decode()))

        # Nikto Scan detected, happens within HTTP Basic Authentication because
        # it happens on the same port.
        payload = packet[TCP].load.decode("ascii").strip()
        if "Nikto" in payload:
            incident_number += 1
            ip_source = packet[IP].src
            print("ALERT #%r: Nikto scan is detected from %r (HTTP)!" % (incident_number, ip_source))
                    
    # see if usernames and passwords sent in-the-clear via IMAP   
    if packet[TCP].dport == 143:
        
        payload = packet[TCP].load.decode("ascii").strip()
        
        if "LOGIN" in payload:
            incident_number += 1
            
            splitted = payload.split()
            username = splitted[2]
            password = splitted[3][1:-1]
            print("ALERT #%r : Usernames and passwords sent in-the-clear (IMAP) (username: %r, password: %r)" % (incident_number, username, password))
            
    # see if usernames and passwords sent in-the-clear via FTP 
    if packet[TCP].dport == 21:
        
        payload = packet[TCP].load.decode("ascii").strip()
        global ftp_username
        global ftp_password
        if "USER" in payload:
            ftp_username = payload.split("USER")[1].strip()
        if "PASS" in payload:
            incident_number += 1
            ftp_password = payload.split("PASS")[1].strip()
            print("ALERT #%r : Usernames and passwords sent in-the-clear (FTP) (username: %r, password: %r)" % (incident_number, ftp_username, ftp_password))

    # NULL Scan detected
    if packet[TCP].flags == "":
        incident_number += 1
        ip_source = packet[IP].src
        print("ALERT #%r: NULL scan is detected from %r (TCP)!" % (incident_number, ip_source))
  
    # FIN Scan detected
    if packet[TCP].flags == "F":
        incident_number += 1
        ip_source = packet[IP].src
        print("ALERT #%r: FIN scan is detected from %r (TCP)!" % (incident_number, ip_source))
    
    # Xmas Scan detected
    if packet[TCP].flags == "FPU":
        incident_number += 1
        ip_source = packet[IP].src
        print("ALERT #%r: Xmas scan is detected from %r (TCP)!" % (incident_number, ip_source))

    # Remote Desktop Protocol (RDP) protocol detected
    if packet[TCP].dport == 3389:
        incident_number += 1
        ip_source = packet[IP].src
        print("ALERT #%r: RDP scan is detected from %r (RDP)!" % (incident_number, ip_source))
        
  except:
    pass

parser = argparse.ArgumentParser(description='A network sniffer that identifies basic vulnerabilities')
parser.add_argument('-i', dest='interface', help='Network interface to sniff on', default='eth0')
parser.add_argument('-r', dest='pcapfile', help='A PCAP file to read')
args = parser.parse_args()
if args.pcapfile:
  try:
    print("Reading PCAP file %(filename)s..." % {"filename" : args.pcapfile})
    sniff(offline=args.pcapfile, prn=packetcallback)    
  except:
    print("Sorry, something went wrong reading PCAP file %(filename)s!" % {"filename" : args.pcapfile})
else:
  print("Sniffing on %(interface)s... " % {"interface" : args.interface})
  try:
    sniff(iface=args.interface, prn=packetcallback)
  except:
    print("Sorry, can\'t read network traffic. Are you root?")
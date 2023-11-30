from scapy.all import sniff
import os
import logging
import csv
import time
from threading import Timer

logfolder = 'logs'
hosts = ['chat.openai.com', 'huggingface.co']
write_interval = 30  # Interval to write to CSV in seconds

logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.INFO)

if not os.path.exists(logfolder):
    os.makedirs(logfolder)

# Store the packets in a list
packets = []

def create_filter(hosts):
    filter_str = '(port 80 or port 443) and ('
    for i, host in enumerate(hosts):
        filter_str += f'host {host}'
        if i != len(hosts) - 1:
            filter_str += ' or '
    filter_str += ')'
    return filter_str

def packet_callback(packet):
    # Check if the packet has IP layer
    if packet.haslayer('IP'):
        src_ip = packet['IP'].src
        dst_ip = packet['IP'].dst
        packets.append((time.strftime("%Y-%m-%d %H:%M:%S"), src_ip, dst_ip))
    logging.info(packet.summary())

def write_to_csv():
    global packets
    if packets:
        timestamp = packets[0][0].replace(" ", "-").replace(":", "-")
        filename = f"{logfolder}/log_{timestamp}.csv"
        with open(filename, 'w', newline='') as csvfile:
            csvwriter = csv.writer(csvfile)
            csvwriter.writerow(['Date and Time', 'Source IP', 'Destination IP'])
            for packet in packets:
                date, src_ip, dst_ip = packet
                csvwriter.writerow([date, src_ip, dst_ip])
        packets = []
    Timer(write_interval, write_to_csv).start()

# Start the timer for writing to CSV
Timer(write_interval, write_to_csv).start()

# Start sniffing
sniff(filter=create_filter(hosts), prn=packet_callback, store=0, iface='en0')

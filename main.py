from scapy.all import sniff
import os
import logging
import csv
import time
from threading import Timer

logfolder = 'logs'
hosts = ['chat.openai.com', 'huggingface.co']
write_interval = 10  # Interval to write to CSV in seconds

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
    packets.append(packet)
    logging.info(packet.summary())

def write_to_csv():
    global packets
    if packets:
        # Updated timestamp format for filename
        timestamp = time.strftime("%Y-%m-%d-%H-%M-%S")
        filename = f"{logfolder}/log_{timestamp}.csv"
        with open(filename, 'w', newline='') as csvfile:
            csvwriter = csv.writer(csvfile)
            csvwriter.writerow(['Date and Time', 'Packet Summary'])
            for packet in packets:
                csvwriter.writerow([time.strftime("%Y-%m-%d %H:%M:%S"), packet.summary()])
        packets = []
    Timer(write_interval, write_to_csv).start()

# Start the timer for writing to CSV
Timer(write_interval, write_to_csv).start()

# Start sniffing
sniff(filter=create_filter(hosts), prn=packet_callback, store=0, iface='en0')

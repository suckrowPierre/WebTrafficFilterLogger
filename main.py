from scapy.all import sniff
import os
import logging

logfolder = 'logs'
hosts = ['chat.openai.com', 'huggingface.co']
write_interval = 30  # Interval to write to CSV

logging.basicConfig(format='%(asctime)s - %(message)s', level=logging.INFO)

if not os.path.exists(logfolder):
    os.makedirs(logfolder)


def create_filter(hosts):
    filter_str = '(port 80 or port 443) and ('
    for i, host in enumerate(hosts):
        filter_str += f'host {host}'
        if i != len(hosts) - 1:
            filter_str += ' or '
    filter_str += ')'
    return filter_str


def packet_callback(packet):
    logging.info(packet.summary())


# Start sniffing
sniff(filter=create_filter(hosts), prn=packet_callback, store=0, iface='en0')

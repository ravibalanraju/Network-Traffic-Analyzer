from scapy.all import sniff, IP, TCP, UDP, ICMP
import pandas as pd
from datetime import datetime
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class PacketCapture:
    def __init__(self, interface='eth0', packet_count=100):
        """
        Initialize packet capture
        
        Args:
            interface: Network interface to capture from
            packet_count: Number of packets to capture (0 for infinite)
        """
        self.interface = interface
        self.packet_count = packet_count
        self.packets_data = []
        
    def packet_callback(self, packet):
        """Process each captured packet"""
        try:
            if IP in packet:
                packet_info = {
                    'timestamp': datetime.now(),
                    'src_ip': packet[IP].src,
                    'dst_ip': packet[IP].dst,
                    'protocol': packet[IP].proto,
                    'length': len(packet),
                    'ttl': packet[IP].ttl
                }
                
                # Add protocol-specific information
                if TCP in packet:
                    packet_info.update({
                        'src_port': packet[TCP].sport,
                        'dst_port': packet[TCP].dport,
                        'protocol_name': 'TCP',
                        'flags': packet[TCP].flags
                    })
                elif UDP in packet:
                    packet_info.update({
                        'src_port': packet[UDP].sport,
                        'dst_port': packet[UDP].dport,
                        'protocol_name': 'UDP',
                        'flags': None
                    })
                elif ICMP in packet:
                    packet_info.update({
                        'src_port': None,
                        'dst_port': None,
                        'protocol_name': 'ICMP',
                        'flags': None
                    })
                else:
                    packet_info.update({
                        'src_port': None,
                        'dst_port': None,
                        'protocol_name': 'Other',
                        'flags': None
                    })
                
                self.packets_data.append(packet_info)
                
                if len(self.packets_data) % 100 == 0:
                    logger.info(f"Captured {len(self.packets_data)} packets")
                    
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
    
    def start_capture(self):
        """Start capturing packets"""
        logger.info(f"Starting packet capture on {self.interface}")
        try:
            sniff(
                iface=self.interface,
                prn=self.packet_callback,
                count=self.packet_count,
                store=False
            )
        except Exception as e:
            logger.error(f"Error during capture: {e}")
            raise
    
    def get_dataframe(self):
        """Convert captured packets to pandas DataFrame"""
        return pd.DataFrame(self.packets_data)
    
    def save_to_csv(self, filename):
        """Save captured data to CSV"""
        df = self.get_dataframe()
        df.to_csv(filename, index=False)
        logger.info(f"Saved {len(df)} packets to {filename}")

# Example usage
if __name__ == "__main__":
    # List available interfaces first
    from scapy.all import get_if_list
    print("Available interfaces:", get_if_list())
    
    # Capture packets
    capturer = PacketCapture(interface='eth0', packet_count=1000)
    capturer.start_capture()
    
    # Save to CSV
    capturer.save_to_csv('data/raw/captured_packets.csv')

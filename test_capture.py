from src.packet_capture import PacketCapture
from scapy.all import get_if_list

# Show available interfaces
print("Available network interfaces:")
for i, iface in enumerate(get_if_list()):
    print(f"{i}: {iface}")

# Choose interface (often 'lo' for localhost, 'eth0' for ethernet, 'wlan0' for wifi)
interface = input("Enter interface name (or press Enter for default): ").strip()
if not interface:
    interface = get_if_list()[0]

print(f"\nCapturing 50 packets from {interface}...")
capturer = PacketCapture(interface=interface, packet_count=50)
capturer.start_capture()

# Display captured data
df = capturer.get_dataframe()
print("\nCaptured Packets Summary:")
print(df.head(10))
print(f"\nTotal packets captured: {len(df)}")
print(f"\nProtocol distribution:\n{df['protocol_name'].value_counts()}")

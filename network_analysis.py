import pyshark
import pandas as pd
import plotly.express as px

# Load the pcap file
cap = pyshark.FileCapture('capture.pcap')

# Function to extract relevant information from a packet
def extract_packet_info(packet):
    try:
        return {
            'timestamp': packet.sniff_time,
            'source': packet.ip.src if 'IP' in packet else None,
            'destination': packet.ip.dst if 'IP' in packet else None,
            'protocol': packet.transport_layer,
            'length': int(packet.length)
        }
    except AttributeError:
        # If packet does not have IP layer or other attributes, return None
        return None

# Extract packet information and filter out None entries
packets_info = [extract_packet_info(packet) for packet in cap if extract_packet_info(packet) is not None]

# Create a DataFrame from the packet information
df = pd.DataFrame(packets_info)

# Convert the timestamp column to datetime format
df['timestamp'] = pd.to_datetime(df['timestamp'])

# Set the timestamp as the index
df.set_index('timestamp', inplace=True)

# Plot the number of packets per minute
df_resampled = df.resample('1T').count()
fig1 = px.bar(df_resampled, x=df_resampled.index, y='protocol', title='Number of Packets per Minute')
fig1.show()

# Top talkers (source and destination IP addresses)
top_sources = df['source'].value_counts().head(10)
top_destinations = df['destination'].value_counts().head(10)

print("Top Sources:\n", top_sources)
print("Top Destinations:\n", top_destinations)

# Protocol distribution
protocol_distribution = df['protocol'].value_counts()

fig2 = px.pie(values=protocol_distribution, names=protocol_distribution.index, title='Protocol Distribution')
fig2.show()

# Packet size analysis
fig3 = px.histogram(df, x='length', nbins=50, title='Packet Size Distribution')
fig3.show()

# 3D scatter plot of network traffic
df_reset = df.reset_index()  # Reset index to use timestamp as a column
fig4 = px.scatter_3d(df_reset, x='timestamp', y='source', z='length', color='protocol',
                     title='3D Scatter Plot of Network Traffic')

# Save the plot as an HTML file
fig4.write_html('3d_scatter_plot.html')

# Open the HTML file in the default web browser
import webbrowser
webbrowser.open('3d_scatter_plot.html')

from flask import Flask, render_template, jsonify
import xmltodict
import json
import pandas as pd
import plotly.express as px
import plotly.utils
import logging
import traceback
from collections import defaultdict

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)

def load_nmap_data():
    try:
        with open('scan.xml', 'r', encoding='utf-8') as file:
            xml_content = file.read()
            logger.debug(f"Successfully read XML file, size: {len(xml_content)} bytes")
            data = xmltodict.parse(xml_content)
            logger.debug("Successfully parsed XML data")
            return data
    except Exception as e:
        logger.error(f"Error loading XML file: {str(e)}")
        logger.error(traceback.format_exc())
        raise

def get_port_range(port):
    try:
        port_num = int(port.split('/')[0])
        if port_num < 1024:
            return 'Well-known (0-1023)'
        elif port_num < 49152:
            return 'Registered (1024-49151)'
        else:
            return 'Dynamic (49152-65535)'
    except:
        return 'Unknown'

def process_nmap_data(data):
    try:
        hosts = []
        ports = []
        services = []
        os_info = defaultdict(list)
        
        if 'nmaprun' in data:
            nmap_data = data['nmaprun']
            logger.debug(f"Nmap data structure: {list(nmap_data.keys())}")
            
            # Handle both single host and multiple hosts
            hosts_data = nmap_data.get('host', [])
            if not isinstance(hosts_data, list):
                hosts_data = [hosts_data]
            
            logger.debug(f"Found {len(hosts_data)} hosts")
            
            for host in hosts_data:
                if not isinstance(host, dict):
                    logger.warning(f"Skipping non-dict host: {type(host)}")
                    continue
                
                # Handle address which is now a list
                address_data = host.get('address', [])
                if isinstance(address_data, list):
                    # Find the IPv4 address
                    ip = next((addr.get('@addr', 'Unknown') for addr in address_data 
                             if addr.get('@addrtype') == 'ipv4'), 'Unknown')
                else:
                    ip = address_data.get('@addr', 'Unknown')
                
                status = host.get('status', {}).get('@state', 'Unknown')
                logger.debug(f"Processing host: {ip} (status: {status})")
                
                # Get OS information
                os_data = host.get('os', {})
                os_name = 'Unknown'
                if isinstance(os_data, dict):
                    os_matches = os_data.get('osmatch', [])
                    if isinstance(os_matches, list) and os_matches:
                        os_name = os_matches[0].get('@name', 'Unknown')
                    elif isinstance(os_matches, dict):
                        os_name = os_matches.get('@name', 'Unknown')
                
                # Handle ports data
                ports_data = host.get('ports', {})
                if not isinstance(ports_data, dict):
                    logger.warning(f"Skipping non-dict ports data for host {ip}")
                    continue
                    
                port_list = ports_data.get('port', [])
                if not isinstance(port_list, list):
                    port_list = [port_list]
                
                logger.debug(f"Found {len(port_list)} ports for host {ip}")
                
                for port in port_list:
                    if not isinstance(port, dict):
                        logger.warning(f"Skipping non-dict port: {type(port)}")
                        continue
                        
                    port_id = port.get('@portid', 'Unknown')
                    protocol = port.get('@protocol', 'Unknown')
                    state = port.get('state', {}).get('@state', 'Unknown')
                    
                    # Handle service information
                    service_info = port.get('service', {})
                    if isinstance(service_info, dict):
                        service = service_info.get('@name', 'Unknown')
                        product = service_info.get('@product', '')
                        version = service_info.get('@version', '')
                    else:
                        service = 'Unknown'
                        product = ''
                        version = ''
                    
                    hosts.append(ip)
                    ports.append(f"{port_id}/{protocol}")
                    services.append({
                        'ip': ip,
                        'service': service,
                        'product': product,
                        'version': version,
                        'state': state,
                        'os': os_name
                    })
                    
                    # Store port information by OS
                    if state == 'open':
                        os_info[os_name].append(f"{port_id}/{protocol}")
        
        logger.debug(f"Processed {len(hosts)} entries")
        return hosts, ports, services, os_info
    except Exception as e:
        logger.error(f"Error processing Nmap data: {str(e)}")
        logger.error(traceback.format_exc())
        raise

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/nmap-data')
def get_nmap_data():
    try:
        data = load_nmap_data()
        hosts, ports, services, os_info = process_nmap_data(data)
        
        # Create port distribution visualization
        port_df = pd.DataFrame({
            'port': ports,
            'count': [1] * len(ports)
        })
        
        # Add protocol and port number columns for sorting
        port_df['protocol'] = port_df['port'].apply(lambda x: x.split('/')[1])
        port_df['port_num'] = port_df['port'].apply(lambda x: int(x.split('/')[0]) if x.split('/')[0].isdigit() else 0)
        port_df['port_range'] = port_df['port'].apply(get_port_range)
        
        # Sort by protocol and port number
        port_df = port_df.sort_values(['protocol', 'port_num'])
        
        # Create port distribution chart
        port_fig = px.bar(
            port_df,
            x='port',
            y='count',
            color='protocol',
            title='Open Ports Distribution by Protocol',
            labels={
                'port': 'Port Number',
                'count': 'Number of Occurrences',
                'protocol': 'Protocol'
            },
            color_discrete_map={
                'tcp': '#1f77b4',
                'udp': '#ff7f0e',
                'Unknown': '#7f7f7f'
            }
        )
        
        # Update layout for better readability
        port_fig.update_layout(
            xaxis_tickangle=-45,
            showlegend=True,
            legend_title_text='Protocol',
            height=600
        )
        
        # Create port range distribution
        port_range_fig = px.pie(
            port_df,
            names='port_range',
            title='Port Range Distribution',
            labels={'port_range': 'Port Range'}
        )
        
        # Create service distribution
        service_fig = px.pie(
            values=[1] * len(services),
            names=[s['service'] for s in services],
            title='Services Distribution'
        )
        
        # Create OS-based port pattern visualization
        os_patterns = []
        for os_name, os_ports in os_info.items():
            if os_ports:  # Only include OSs with open ports
                os_patterns.append({
                    'os': os_name,
                    'ports': ', '.join(sorted(set(os_ports))),
                    'port_count': len(set(os_ports))
                })
        
        os_patterns_df = pd.DataFrame(os_patterns)
        os_pattern_fig = px.bar(
            os_patterns_df,
            x='os',
            y='port_count',
            title='Open Ports by Operating System',
            labels={'os': 'Operating System', 'port_count': 'Number of Unique Open Ports'}
        )
        
        return jsonify({
            'hosts': hosts,
            'ports': ports,
            'services': services,
            'os_patterns': os_patterns,
            'port_chart': json.dumps(port_fig, cls=plotly.utils.PlotlyJSONEncoder),
            'port_range_chart': json.dumps(port_range_fig, cls=plotly.utils.PlotlyJSONEncoder),
            'service_chart': json.dumps(service_fig, cls=plotly.utils.PlotlyJSONEncoder),
            'os_pattern_chart': json.dumps(os_pattern_fig, cls=plotly.utils.PlotlyJSONEncoder)
        })
    except Exception as e:
        logger.error(f"Error in get_nmap_data: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            'error': str(e),
            'hosts': [],
            'ports': [],
            'services': [],
            'os_patterns': [],
            'port_chart': None,
            'port_range_chart': None,
            'service_chart': None,
            'os_pattern_chart': None
        }), 500

if __name__ == '__main__':
    app.run(debug=True) 
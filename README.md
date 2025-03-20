# Nmap Scan Visualization Tool

A web-based visualization tool for analyzing Nmap scan results. This application takes Nmap XML output and presents it in an interactive, user-friendly interface with various charts and data visualizations.

## Features

### 1. Port Analysis
- Interactive bar chart showing open ports distribution by protocol (TCP/UDP)
- Pie chart displaying port range distribution (Well-known, Registered, Dynamic ports)
- Color-coded visualization for different protocols
- Sortable and filterable port information

### 2. Service Analysis
- Service distribution visualization
- Detailed service information including product names and versions
- State indicators for each service (open/closed)

### 3. Operating System Analysis
- OS detection results visualization
- Port patterns by operating system
- Detailed breakdown of open ports per OS

### 4. Detailed Information
- Comprehensive table view with all scan details
- IP address information
- Service versions and states
- Product information
- Interactive and sortable data presentation

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd nmap_analysis
```

2. Create a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install the required dependencies:
```bash
pip install -r requirements.txt
```

## Usage

1. Generate an Nmap XML output file:
```bash
nmap -A -T4 -oX scan.xml <target>
```

2. Place the `scan.xml` file in the project root directory.

3. Run the Flask application:
```bash
python app.py
```

4. Open your web browser and navigate to:
```
http://localhost:5000
```

## Requirements

- Python 3.7+
- Flask
- xmltodict
- plotly
- pandas

See `requirements.txt` for specific version requirements.

## Features in Detail

### Port Analysis
- Visualizes port distribution across protocols
- Groups ports into meaningful categories:
  - Well-known ports (0-1023)
  - Registered ports (1024-49151)
  - Dynamic ports (49152-65535)

### Service Analysis
- Shows service distribution across hosts
- Provides detailed service information:
  - Service name
  - Product details
  - Version information
  - Current state

### OS Detection
- Displays detected operating systems
- Shows port patterns specific to each OS
- Provides correlation between services and OS

## Browser Compatibility

The application has been tested and works with:
- Google Chrome (recommended)
- Mozilla Firefox
- Microsoft Edge
- Safari

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a new Pull Request

## Citation

If you use this tool in your research or work, please cite it as:
Miro Rava - py-nmap Viewer

## Acknowledgments

- Built with Flask web framework
- Visualizations powered by Plotly.js
- Styling with Bootstrap 5
- XML parsing with xmltodict 
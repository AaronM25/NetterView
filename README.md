
# NetterView

NetterView is a browser-based network monitoring and visualization tool designed to discover, analyze, and monitor devices on a local network.

It provides an interactive network topology, device identification, latency monitoring, port scanning, network health checks, shared-drive detection, scan history, security risk analysis, and AI-assisted network analysis.

## Features
🔍 Network Discovery
Discovers devices using ARP scanning
Uses ping scanning as a fallback
Identifies IP and MAC addresses
🖥️ Device Identification
Detects device vendors using MAC addresses
Classifies devices such as routers, laptops, phones, printers, cameras, TVs, consoles, and IoT devices
Performs reverse DNS lookups
🗺️ Network Topology
Displays discovered devices in an interactive network map
Identifies the network gateway
Visualizes device-to-gateway relationships
📊 Network Monitoring
Measures device latency
Tracks device availability
Detects new, updated, unchanged, and offline devices
Supports recurring automatic scans
🔐 Security Analysis
Scans for open TCP ports
Detects potentially risky services
Identifies common security exposures
Provides severity ratings and security recommendations
Supports CVE-based vulnerability signatures
💾 Scan History
Stores previous network scans
Tracks changes between scans
Saves device snapshots and open-port information
🤖 AI Network Analysis
Uses Ollama and Llama 3.2 to analyze network scan results
Allows users to ask questions about their network
Generates network summaries and security insights
Technology Stack

## Backend

Python
Flask
SQLAlchemy
SQLite

## Network Scanning

Scapy
ping3
Nmap
psutil
Socket / DNS

## Device Identification

MAC vendor lookup
manuf database
Vendor-based device classification

## AI

Ollama
Llama 3.2

## Frontend

HTML
CSS
JavaScript
Vis.js

## How It Works

NetterView identifies the active network interface.
The network subnet is calculated from the local IP address and netmask.
An ARP sweep discovers devices on the network.
Ping scanning is used to find devices missed by ARP.
Devices are enriched with hostname, vendor, device type, and latency information.
Results are stored in a SQLite database.
NetterView compares the current scan with previous scans to identify changes.
Users can perform additional port, health, and shared-drive scans.
Security findings are analyzed and displayed through the dashboard.
Network data can be analyzed using the integrated Ollama AI assistant.

## Project Structure
NetterView/
│
├── app/
│   ├── models.py       # Database models and data management
│   ├── routes.py       # API routes and network functionality
│   ├── scanner.py      # ARP and ping network scanning
│   └── ...
│
├── data/
│   └── manuf           # MAC vendor database
│
├── templates/          # Frontend templates
├── static/             # CSS and JavaScript
├── netscope.db         # SQLite database
└── ...
## Installation

Clone the repository:

git clone https://github.com/YOUR-USERNAME/NetterView.git
cd NetterView

Create a virtual environment:

python -m venv venv

Activate the virtual environment on Windows:

venv\Scripts\activate

Install the required dependencies:

pip install -r requirements.txt
Running NetterView

Start the Flask application:

python run.py

Then open the application in your web browser.

## Requirements

NetterView is designed to run on a computer connected to a local network. Some scanning features may require elevated permissions depending on the operating system and network configuration.

For AI network analysis, Ollama must be installed and the configured Llama model must be available locally.

## **Security Notice**

**NetterView is intended for authorized network monitoring and educational purposes. Only scan networks and devices that you own or have permission to monitor.**

## Project

NetterView was developed as a senior project focused on network discovery, monitoring, visualization, and security analysis.
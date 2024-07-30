PacketWhisper is a Python tool for capturing and analyzing network packets. It provides essential insights for network security and performance optimization.

Features
Real-time network packet capture.
Display of captured data in an intuitive graphical interface.
Support for TCP, UDP, and ICMP protocols.
Export of captured data in various formats: CSV, JSON, XML.
Selection of available network interfaces.
Integration with ChatGPT API for advanced packet analysis and insights.
API Usage
PacketWhisper integrates with the ChatGPT API to provide enhanced analysis of network packets. Here’s how it works:

Scapy: A powerful Python library for network packet manipulation and capture, used for sniffing packets and processing packet data.
PyQt5: A Python binding for the Qt framework, used for creating the graphical user interface (GUI) of the application.
Pandas: A data manipulation library that handles and exports captured data in various formats.
ChatGPT API: Used for analyzing the captured network data, providing insights, and generating detailed explanations of network traffic patterns and anomalies.

Prerequisites
Ensure you have Python installed on your system. This project has been tested with Python 3.12. You will also need to install the required dependencies using the requirements.txt file.

Additionally, you'll need an API key for the ChatGPT API to enable advanced packet analysis. You can obtain an API key from OpenAI.

Installation : 

1. Clone the repository:
git clone https://github.com/Raiizer08/PacketWhisper.git
cd PacketWhisper

2. Create a virtual environment (optional but recommended):
python -m venv env
source env/bin/activate  # On Windows, use `env\Scripts\activate`

3. Install the dependencies:
pip install -r requirements.txt

4. Set up your ChatGPT API key:

Save your ChatGPT API key in an environment variable or configuration file. For example:

export CHATGPT_API_KEY='your-api-key-here'

Usage:

1.Launch the application:
python interface.py

2. Select a network interface from the dropdown menu in the graphical interface.

Click "Start Sniffer" to begin capturing packets.

3. View the captured packets in the table within the graphical interface.

4. Export the captured data using the "Output Format" menu to choose between CSV, JSON, or XML formats.

5. Analyze captured data using the ChatGPT integration. The application will send the packet data to the ChatGPT API for analysis, providing insights and detailed explanations directly in the GUI.

Development
To contribute to the project, please follow these steps:

1. Fork the repository.

2. Create a branch for your changes:
git checkout -b your-branch-name

3. Make your changes and commit them:
git commit -am 'Description of your changes'

4. Push your changes:
git push origin your-branch-name

5. Open a pull request on GitHub to propose your changes.

Authors:
Raiizer and Luminox

License
This project is licensed under the MIT License. See the LICENSE file for more details.

Contact
For any questions or support, please email pkto.riann@example.com.

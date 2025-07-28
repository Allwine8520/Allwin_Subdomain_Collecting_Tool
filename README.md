# Allwin_Subdomain_Collecting_Tool

Allwin Advanced Subdomain Collecting Tool
Allwin Advanced Subdomain Collecting Tool is a powerful, user-friendly Python GUI application designed for fast and reliable subdomain enumeration. Using DNS-based multithreaded scanning, it efficiently discovers live subdomains, providing real-time progress and results display with an intuitive and attractive interface.

**Features**
DNS-based subdomain discovery: Uses A record lookups for accurate results beyond simple HTTP probing.

Multithreaded scanning: Leverages Python's ThreadPoolExecutor to scan many subdomains concurrently, significantly speeding up enumeration.

User-friendly GUI: Built with Tkinter using modern ttk styling, providing a clean and responsive user experience.

Customizable parameters: Set domain, subdomain wordlist, DNS query timeout, and thread count.

Start/Stop control: Easily start and safely stop ongoing scans.

Live progress and logging: View found subdomains and current status dynamically in the GUI.

Export results: Save discovered subdomain names (without IPs) to TXT or CSV files.

Ideal for: Penetration testers, security researchers, and network administrators assessing domain attack surfaces.

**Requirements**
Python 3.x

dnspython library (for DNS resolution)

Install dnspython via pip:
**pip install dnspython**

Installation
Clone or download this repository:
git clone https://github.com/yourusername/allwin-subdomain-collector.git

Navigate to the project folder:
cd allwin-subdomain-collector

**Install dependencies:**
pip install dnspython

Prepare a subdomain wordlist file (default: subdomains.txt in the project root). You can use your own wordlist or download popular ones like SecLists.

**Run the tool:**
python main.py

**Steps:**
Enter the target domain you want to enumerate (e.g., example.com).

Choose the subdomain wordlist file or keep the default subdomains.txt.

Set the DNS query timeout in seconds (default 3).

Set the number of scanning threads (default 10).

Click Start Scan to begin enumerating subdomains.

Watch live progress and discovered subdomains in the results pane.

Optionally, click Stop Scan to safely interrupt scanning.

Once complete, click Export Results to save subdomains (without IPs) in TXT or CSV format.

Screenshots
(Add screenshots here to showcase the GUI, scanning in progress, and export dialog.)
<img width="993" height="670" alt="image" src="https://github.com/user-attachments/assets/38cb3370-68b4-4748-a802-27f1b7b0f19f" />

License
This project is licensed under the MIT License - see the LICENSE file for details.

Contributing
Contributions and suggestions are welcome! Feel free to open issues for bugs or feature requests and submit pull requests for improvements.

Happy subdomain enumeration! 🚀

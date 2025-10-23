# ELEVATE-LABS-CYBERSECURITY-INTERNSHIP-PROJECT

**Project Title:** Log File Analyzer for Intrusion Detection

**Description:**
The Log File Analyzer for Intrusion Detection is a Python-based tool that monitors and analyzes server logs to detect suspicious activities and potential security breaches. It processes Apache web server logs and SSH authentication logs to identify patterns indicative of brute-force attacks, port scanning, and denial-of-service (DoS) attempts. By extracting key information such as IP addresses, timestamps, and login outcomes, the tool helps system administrators quickly recognize and respond to security threats.

The analyzer uses **regex** to parse log entries and **pandas** to organize data for further analysis. Suspicious IPs are flagged based on configurable thresholds, such as repeated failed login attempts within a short period. The tool also cross-references IP addresses with public blacklists to highlight known malicious sources.

Visualizations generated using **matplotlib** provide insights into access patterns, including the most active IP addresses, frequency of failed login attempts, and time-based attack trends. These visual representations help security teams quickly understand the scope and timing of attacks.

All detected incidents are exported to **CSV reports**, containing details such as the source IP, number of failed attempts, and time of first and last attempts, making it easier to review and share with other team members or for audit purposes.

This project demonstrates practical applications of log parsing, data analysis, and cybersecurity monitoring. It equips administrators with actionable insights and automated detection capabilities to enhance the security posture of their systems.

**Key Features:**

* Parses Apache and SSH logs efficiently
* Detects brute-force, scanning, and DoS attack patterns
* Cross-references with public IP blacklists
* Visualizes access patterns and attack trends
* Exports detailed incident reports in CSV format

**Technologies Used:** Python, pandas, regex, matplotlib

---

### 📂 Project Structure

```
log-analyzer/
├── README.md
├── requirements.txt
├── config.yaml
├── main.py
├── parsers.py
├── analyzer.py
├── visualizer.py
├── blacklist.py
├── utils.py
├── example_logs/
│   ├── apache_sample.log
│   └── ssh_sample.log
└── outputs/
    ├── reports/
    └── plots/

---

###  How to Run

1. **Clone the repository:**

   ```bash
   git clone https://github.com/yourusername/log-file-analyzer.git
   cd log-file-analyzer
   ```

2. **Create & activate a virtual environment (Windows):**

   ```bash
   python -m venv venv
   venv\Scripts\activate
   ```

   *(For Linux/Mac: `source venv/bin/activate`)*

3. **Install dependencies:**

   ```bash
   pip install -r requirements.txt
   ```

4. **Run the analyzer:**

   ```bash
   python main.py --apache example_logs/apache_large_sample.log --ssh example_logs/ssh_large_sample.log --year 2025
   ```

---

### 📊 Output

* **Reports:** `outputs/reports/incidents.csv` – Detected suspicious IPs and patterns
* **Visualizations:** `outputs/plots/` – Graphs showing access and attack trends

---

### 🧠 Internship Context

This project was developed as part of a **Cybersecurity Internship Program** to demonstrate practical skills in log analysis, data visualization, and automated intrusion detection using Python.

---

### 🏁 Future Improvements

* Integration with real-time log monitoring
* Email or dashboard alert system
* IP reputation scoring with online threat databases

---

### 👨‍💻 Author

NAME: **Arjun Thatikonda**
Intern – Cybersecurity
GitHub: [ARJUN1675](https://github.com/ARJUN1675)

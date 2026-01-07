# 🚀 DNS Tunneling Detection: Production Upgrade Guide

This guide outlines the steps to transform your research project into a **Production-Ready Security Tool**. Completing these steps will demonstrate to recruiters your ability to build, deploy, and operationalize machine learning models for cybersecurity.

## 📋 The 4-Step Upgrade Plan

1.  **Refactor**: Modularize code for reusability.
2.  **Real-Time Detection**: Implement a live packet sniffer.
3.  **Visualization**: Build an interactive dashboard.
4.  **Deployment**: Dockerize the application.

---

## Part 1: Refactoring for Production

**Why?** Recruiters want to see clean, maintainable code, not just Jupyter notebooks or loose scripts. separating concerns (e.g., feature extraction vs. main logic) is critical.

### 1.1 Standardize Feature Extraction
You need a single source of truth for how features are generated so that your *training* and *inference* (live detection) pipelines are identical.

**Action:**
Create a file `app/features.py`. This module will contain all your math and string processing logic.
*   **Key Insight:** If you change a feature definition here, it updates everywhere.
*   **Code:** (I have started this file for you in `app/features.py`). Review it and ensure it matches the features used in your training script.

### 1.2 Update Training Script
Modify your training script to import from `app/features.py` instead of redefining functions locally.

**Action:**
1.  Move `experimentation/src/train_model.py` logic to a cleaner script or update it.
2.  Ensure it saves the model to the `models/` directory for better organization.

```python
# In your training script
import joblib
# ... training logic ...
joblib.dump(clf, "models/random_forest_model.pkl")
```

---

## Part 2: Real-Time Detection (The "Sniffer")

**Why?** Analyzing old PCAP files is "Forensics". Analyzing live traffic is "Detection". The latter is much more impressive for a security engineering role.

### 2.1 The Sniffer Logic
We will use the library `scapy` to listen to the network interface, filter for DNS packets (UDP port 53), and extract the query.

**Key Challenges to Solve:**
*   **Performance:** Python is slow. How do you handle high packet volumes? (Answer: Use a queue system to decouple sniffing from processing).
*   **Filtering:** Filter out your own noise (e.g., browsing traffic) vs. potential tunnel traffic.

**Action:**
Review the `start_sniffing` function I sketched out in `app/dashboard.py`. It uses a background thread `threading.Thread` to sniff without freezing the UI.

---

## Part 3: Interactive Dashboard

**Why?** A CLI output saying "Malicious" is boring. A dashboard with a live graph and red alert boxes is what gets people hired. It shows you understand **Security Operations (SecOps)** needs.

**Tools:** We will use **Streamlit** because it is pure Python and very fast to build.

### 3.1 Build the UI
**Action:**
Building on `app/dashboard.py`, try to implement the following features yourself:
1.  **Metric Cards:** Show "Total Packets", "Safe", "Malicious".
2.  **Data Table:** A live-updating table of the last 100 DNS queries.
3.  **Visuals:** A pie chart of Safe vs. Malicious traffic.

**Challenge:**
*   Make the dashboard play a sound or show a huge red banner when a probability > 0.9 is detected.

---

## Part 4: Containerization (Docker)

**Why?** "It works on my machine" is not acceptable in big tech. Docker ensures your tool runs anywhere (cloud, colleague's laptop, server).

### 4.1 Create a Dockerfile
Create a file named `Dockerfile` in the root directory.

**Draft Content:**
```dockerfile
# Base Image
FROM python:3.9-slim

# Install system dependencies (libpcap is needed for scapy)
RUN apt-get update && apt-get install -y libpcap-dev && rm -rf /var/lib/apt/lists/*

# Work Directory
WORKDIR /app

# Install Python Deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy Code
COPY . .

# Run Command
CMD ["streamlit", "run", "app/dashboard.py", "--server.port=8501", "--server.address=0.0.0.0"]
```

### 4.2 Build and Run
```bash
docker build -t dns-guard .
docker run -p 8501:8501 dns-guard
```

---

## 📚 Bonus Learning: "The Meta-Game"

To really impress a recruiter, you need to be able to talk about the **limitations** of your tool.

**Study these concepts:**
1.  **False Positives:** What happens if a legit domain has a high entropy? (e.g., `cdn.amazon.d3d3f3.com`). How would you whitelist this?
2.  **Encrypted DNS:** How does this tool handle DoH (DNS over HTTPS)? (Hint: It probably can't right now. That's a great "Future Work" talking point).
3.  **Performance:** Scapy is too slow for 10Gbps links. In production, you'd use C++ or eBPF (XDP). Mentioning "eBPF" in an interview is a power move.

---

## Next Steps needed to "Boot" the project
1.  **Retrain the model:** Your model file is missing. Run the training script ensuring the `features.py` logic is used.
2.  **Save the model:** Save it to `models/random_forest_model.pkl`.
3.  **Run the App:** `streamlit run app/dashboard.py`

Good luck! You got this.

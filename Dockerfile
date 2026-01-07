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
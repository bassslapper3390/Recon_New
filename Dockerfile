FROM kalilinux/kali-rolling:latest

ENV DEBIAN_FRONTEND=noninteractive \
	PYTHONDONTWRITEBYTECODE=1 \
	PYTHONUNBUFFERED=1 \
	RUNNING_IN_DOCKER=1

# Base tools and languages
RUN apt-get update && apt-get install -y --no-install-recommends \
	python3 python3-venv python3-dev build-essential git curl wget ca-certificates \
	libpcap-dev libpcap0.8-dev \
	nmap masscan nikto amass gobuster ffuf feroxbuster whatweb wafw00f \
	golang \
	&& rm -rf /var/lib/apt/lists/*

# Project directory
WORKDIR /app

# Copy requirements and install
COPY requirements.txt ./

# Create venv and install deps inside it
RUN python3 -m venv /opt/venv \
	&& /opt/venv/bin/pip install --upgrade pip \
	&& /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

# Install ProjectDiscovery tools via Go
ENV PATH="/opt/venv/bin:$PATH" GOPATH=/root/go PATH=/root/go/bin:/usr/local/go/bin:/usr/bin:/bin:$PATH
# Install only essential Go tools that don't require pcap
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
	&& go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest \
	&& go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
	&& go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest

# Copy source
COPY . .

EXPOSE 8088

# Use the virtual environment's uvicorn
CMD ["/opt/venv/bin/uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8088", "--workers", "1"]

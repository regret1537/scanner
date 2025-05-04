FROM python:3.10-slim
WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends nmap dnsutils && \
    rm -rf /var/lib/apt/lists/*

# Copy Python dependencies and config
COPY requirements.txt config.yaml ./
# Install Python packages
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install sublist3r

# Copy application code
COPY . .

EXPOSE 5000
CMD ["gunicorn", "-b", "0.0.0.0:5000", "app:app"]
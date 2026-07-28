FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    nmap \
    openssh-client \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy application files
COPY pynetworkintel/ /app/pynetworkintel/
COPY setup.py requirements.txt /app/

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Install the application
RUN pip install --no-cache-dir -e .

# Create config directory
RUN mkdir -p ~/.pynetworkintel

# Set entrypoint
ENTRYPOINT ["pynetworkintel"]

# Default to help
CMD ["--help"]

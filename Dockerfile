FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    nmap \
    openssh-client \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy application files
COPY pynetworkintel/ /app/pynetworkintel/
COPY pyproject.toml README.md LICENSE /app/

# Install the application (pyproject.toml is the sole build metadata source;
# there is no setup.py or requirements.txt install path anymore)
RUN pip install --no-cache-dir .

# Create config directory
RUN mkdir -p ~/.pynetworkintel

# Set entrypoint
ENTRYPOINT ["pynetworkintel"]

# Default to help
CMD ["--help"]

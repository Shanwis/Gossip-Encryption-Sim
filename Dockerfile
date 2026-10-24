FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Install system network tools (iproute2 for ip/tc, iptables for fallback loss emulation)
# and procps for process management and PID validation
RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    iptables \
    procps \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

# Copy project files and install package in editable mode with development dependencies
COPY . /workspace/
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -e ".[dev]"

CMD ["/bin/bash"]

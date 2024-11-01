FROM python:3.9-slim

RUN apt-get update && apt-get install -y \
    curl \
    git \
    apt-transport-https \
    && rm -rf /var/lib/apt/lists/* /usr/share/doc /usr/share/man

RUN echo "deb [trusted=yes] https://apt.fury.io/bearer/ /" | tee -a /etc/apt/sources.list.d/fury.list \
    && apt-get update \
    && apt-get install -y bearer

RUN python3 -m pip install semgrep \
    && curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY scanner/*.py /app/

RUN chmod +x /app/*.py && ls -la /app

ENTRYPOINT ["python3", "/app/sast_scanner.py"]

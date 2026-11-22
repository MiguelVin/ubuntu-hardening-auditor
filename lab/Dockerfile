# Deliberately VULNERABLE Ubuntu for testing hardaudit.
# Never expose this container to a network. See lab/README in the main README.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       openssh-server sudo ufw libpam-pwquality python3 python3-venv \
    && rm -rf /var/lib/apt/lists/*

# Install hardaudit from this repository
COPY pyproject.toml README.md LICENSE /opt/hardaudit/
COPY src /opt/hardaudit/src
RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir /opt/hardaudit \
    && ln -s /opt/venv/bin/hardaudit /usr/local/bin/hardaudit

# Break the system on purpose
COPY lab/misconfigure.sh lab/entrypoint.sh /usr/local/sbin/
RUN bash /usr/local/sbin/misconfigure.sh

CMD ["bash", "/usr/local/sbin/entrypoint.sh"]

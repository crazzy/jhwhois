# hadolint global ignore=DL3008
FROM ubuntu:22.04

RUN apt-get update && \
	apt-get -y --no-install-recommends install python3 python3-pip locales git && \
	apt-get clean && \
	rm -rf /var/lib/apt/lists/*

WORKDIR /opt

RUN git clone https://github.com/crazzy/jhwhois.git

WORKDIR /opt/jhwhois

RUN pip3 install --no-cache-dir -r requirements

# TODO: Figure out how to pass a commandline to this
ENTRYPOINT ["python3", "/opt/jhwhois/jhwhois.py"]

FROM tim_python_v3.10:latest AS base
#  FROM python:3.11-alpine AS base

# Copy the connector
COPY src /opt/opencti-connector-import-document

#  requirements.txt must have pycti removed
RUN sed -i 's/^pycti==.*$//' /opt/opencti-connector-import-document/requirements.txt 

# Install Python modules
# hadolint ignore=DL3003
RUN echo "~~~ Starting DOCUMENT IMPORTER CONNECTOR ... " \
    && apk --no-cache add \
    build-base libmagic libffi-dev libxml2-dev libxslt-dev libffi-dev openssl-dev rust cargo \
    && cd /opt/opencti-connector-import-document \
    && pip3 install --no-cache-dir -r requirements.txt \
    && apk del build-base \
    && echo " ... DOCUMENT IMPORTER CONNECTOR Done ~~~"

#############################
## debugger
## debugpy should be installed in the base python image
#############################

FROM base as debugger

ENTRYPOINT ["python","-m","debugpy","--listen","0.0.0.0:5677", "--wait-for-client", "src/main.py"]

#############################
## primary
#############################

FROM base as primary

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]

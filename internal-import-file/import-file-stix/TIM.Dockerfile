# FROM python:3.11-alpine
FROM tim_python_v3.10:latest AS base

# Copy the connector
COPY src /opt/opencti-connector-import-file-stix

#  requirements.txt must have pycti removed
RUN sed -i 's/^pycti==.*$//' /opt/opencti-connector-import-file-stix/requirements.txt 

# Install Python modules
# hadolint ignore=DL3003
RUN apk --no-cache add \
    build-base libmagic libffi-dev libxml2-dev libxslt-dev gfortran musl-dev g++ openblas openblas-dev \
    && cd /opt/opencti-connector-import-file-stix \
    && pip3 install --no-cache-dir -r requirements.txt \
    && apk del build-base gfortran musl-dev g++ openblas-dev

#############################
## debugger
## debugpy should be installed in the base python image
#############################

FROM base as debugger

ENTRYPOINT ["python","-m","debugpy","--listen","0.0.0.0:5678", "--wait-for-client", "import-file-stix.py"]

#############################
## primary
#############################

FROM base as primary

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]

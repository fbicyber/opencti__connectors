FROM tim_python_v3.10:latest AS base

# Copy the connector src code
COPY src /opt/opencti-connector-actor-import

#  requirements.txt must have pycti removed
# pycti is already installed in the base image
RUN sed -i 's/^pycti==.*$//' /opt/opencti-connector-actor-import/requirements.txt \
    && cat /opt/opencti-connector-actor-import/requirements.txt

##############################################################################################
# Upgrade PIP and wheel
##############################################################################################
# RUN pip3 install --upgrade pip wheel
# ##############################################################################################
# # Fixes the AttributeError: cython_sources error on build
# ##############################################################################################
# RUN pip3 install "Cython>=3.0" "pyyaml>=6" --no-build-isolation
##############################################################################################

# Install Python modules
# hadolint ignore=DL3003
RUN echo "~~~ Starting ACTOR IMPORTER CONNECTOR ... " \
    && apk --no-cache add build-base libmagic libffi-dev libxml2-dev libxslt-dev \
    && cd /opt/opencti-connector-actor-import \
    && pip3 install --no-cache-dir -r requirements.txt \
    && apk del build-base \
    && echo "... ACTOR IMPORTER CONNECTOR Done ~~~"

#############################
## debugger
## debugpy should be installed in the base python image
#############################

FROM base as debugger
ENTRYPOINT ["python","-m","debugpy","--listen","0.0.0.0:5676", "--wait-for-client", "main.py"]

#############################
## primary
#############################

FROM base as primary
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
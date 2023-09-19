# Container Debugging

Multiple steps are required in order to debug code running in containers.  This discussion focuses on the [Import Extraction Connector](./internal-import-file/import-extraction) but can apply to any of the other repos or Connectos being run in containers.

# Setup

## Python Base

The Python base container must have the 'debugpy' module installed.

## Dockerfile

The Dockerfile should have two 'target' entries, a 'debugger' target and a 'primary' target.

```
FROM tim_python_v3.10:latest AS base
    .
    .
    .

#############################
## debugger
## debugpy should be installed in the base python image
#############################

FROM base as debugger
ENTRYPOINT ["python","-m","debugpy","--listen","0.0.0.0:5679", "--wait-for-client", "src/main.py"]

#############################
## primary
#############################

FROM base as primary
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
```

## Docker Compose

The docker-compose file should have the following entries for the debugger:

```
    build:
        dockerfile: TIM.Dockerfile
        # target: primary
        target: debugger
```

```
    ports:
      - 5679:5679  # for debugger
```
Setting up the volumes allows you to modify the codebase in VSCode and then to just restart the container, in order to see the changes.
```
    volumes:
        - ./:/opt/opencti-connector-import-extraction
```


```
version: '3'
services:
  connector-import-extraction:
    container_name: opencti-connector-import-extraction
    working_dir: /opt/opencti-connector-import-extraction
    volumes:
        - ./:/opt/opencti-connector-import-extraction
    build:
      dockerfile: TIM.Dockerfile
      # target: primary
      target: debugger
    restart: always
    ports:
      - 5679:5679  # for debugger
```

## VSCode Debugger Launch File

For each container, you wish to debug must have an entry in the Launch file like this:

```
    {
        "name": "Import Extraction: Remote Attach",
        "type": "python",
        "request": "attach",
        "connect": {
            "host": "localhost",
            "port": 5679
        },
        "pathMappings": [
            {
                "localRoot": "${workspaceFolder}/internal-import-file/import-extraction",
                "remoteRoot": "."
            }
        ],
        "justMyCode": true,
    },
```

## OpenCTI

The Connectors will not show as active in OpenCTI until you have attached to them with the debugger, if they have been setup in this way.

## Debugging Done and/ or Switching to Production-mode

1) Within the docker-compose file, change the 'target' setting back to 'primary'.

```
    build:
        dockerfile: TIM.Dockerfile
        target: primary
        # target: debugger
```

2) Comment out the 'ports' entry:

```
    ports:
      - 5679:5679  # for debugger
```
3) Comment out the 'volumes' entry:

```
    volumes:
        - ./:/opt/opencti-connector-import-extraction
```
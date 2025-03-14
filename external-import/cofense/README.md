# OpenCTI Cofense Connector

<!-- 
General description of the connector 
* What it does
* How it works
* Special requirements
* Use case description
* ...
-->

## Installation

### Requirements

- OpenCTI Platform >= 5.3.7

### Configuration

| Parameter                    | Docker envvar                | Mandatory | Description                                                                                   |
|------------------------------|------------------------------|-----------|-----------------------------------------------------------------------------------------------|
| `opencti_url`                | `OPENCTI_URL`                | Yes       | The URL of the OpenCTI platform.                                                              |
| `opencti_token`              | `OPENCTI_TOKEN`              | Yes       | The default admin token configured in the OpenCTI platform parameters file.                   |
| `connector_id`               | `CONNECTOR_ID`               | Yes       | A valid arbitrary `UUIDv4` that must be unique for this connector.                            |
| `connector_type`             | `CONNECTOR_TYPE`             | Yes       | Must be `EXTERNAL_IMPORT` (this is the connector type).                                       |
| `connector_name`             | `CONNECTOR_NAME`             | Yes       | Option `CofenseIntel`                                                                         |
| `connector_scope`            | `CONNECTOR_SCOPE`            | Yes       | Supported scope: Template Scope (MIME Type or Stix Object)                                    |
| `connector_log_level`        | `CONNECTOR_LOG_LEVEL`        | Yes       | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose). |
| `interval_sec`               | `COFENSEINTEL_INTERVAL`      | Yes       | The number of interval in seconds                                                             |
| `user_token`                 | `COFENSEINTEL_USER`          | Yes       | User token for the Cofense Intelligence SDK                                                   |
| `user_pass`                  | `COFENSEINTEL_PASSWORD`      | Yes       | User password for the Cofense Intelligence SDK                                                |

### Debugging ###

<!-- Any additional information to help future users debug and report detailed issues concerning this connector --> 

### Additional information

<!-- 
Any additional information about this connector 
* What information is ingested/updated/changed
* What should the user take into account when using this connector
* ...
-->


import json
import os
import sys
import time
from typing import Dict

import stix2
from helper import get_config, get_helper
from process_file import FileProcessor
from pycti import Identity, ThreatActorIndividual, get_config_variable


class ActorImporter:
    def __init__(self) -> None:
        self.config = get_config()
        self.helper = get_helper(config=self.config)
        self.author = self.make_author()

    def _process_message(self, data: Dict) -> str:
        """Main processing loop for the connector.
        Args:
            data (Dict): _description_
        Returns:
            str: _description_
        """
        self.helper.log_info("Processing new message")
        file_name = self._download_import_file(data)
        processor = FileProcessor(self.config, self.helper, self.author)
        recs = processor.get_recs(file_name)
        validated_recs = processor.validate_recs(recs)
        bundle = self.create_bundle(validated_recs)
        bypass_validation = False
        bundles_sent = self.send_bundle(bundle)
        self.helper.log_info("Bundles sent: " + str(len(bundles_sent)))
        if self.helper.get_validate_before_import() and not bypass_validation:
            return "Generated bundle sent for validation"
        else:
            return str(len(bundles_sent)) + " generated bundle(s) for worker import"

    def create_bundle(self, recs):
        """Creates serialized STIX Bundle object from the provided lists
          of STIX Observables, Indicators, and Relationships

        :param indicators: List of STIX Indicator objects
        :return: Serialized STIX Bundle object
        """
        self.helper.log_info("Creating STIX Bundle")
        recs.append(self.author)

        bundle = stix2.Bundle(objects=recs, allow_custom=True).serialize()
        return bundle

    def make_author(self):
        _CONNECTOR_NAME = get_config_variable(
            "CONNECTOR_NAME", ["connector", "name"], self.config
        ).capitalize()

        author = stix2.Identity(
            # author = self.helper.api.identity.create(
            # author = Identity(
            id=Identity.generate_id(_CONNECTOR_NAME, "organization"),
            name=_CONNECTOR_NAME,
            identity_class="Organization",
            description="Data ingested by the Actor Importer",
            confidence=self.helper.connect_confidence_level,
        )
        return author

    def send_bundle(self, bundle):
        """
        Attempts to send serialized STIX Bundle to OpenCTI client

        :param bundle: Serialized STIX Bundle
        """
        self.helper.log_info("Sending STIX Bundle")
        try:
            return self.helper.send_stix2_bundle(
                bundle=bundle,
                update=True,
                bypass_validation=False,
            )
        except Exception as e:
            self.helper.log_debug("Sending bundle again: ", str(e))
            time.sleep(60)
            try:
                return self.helper.send_stix2_bundle(
                    bundle=bundle, update=True, bypass_validation=False
                )
            except Exception as e:
                self.helper.log_error(str(e))

    def start(self) -> None:
        """Starts the main loop"""
        self.helper.listen(self._process_message)

    def _download_import_file(self, data: Dict) -> str:
        """Downloads file to connector

        Args:
            data (Dict): _description_

        Returns:
            str: _description_
        """
        file_fetch = data["file_fetch"]
        file_uri = self.helper.opencti_url + file_fetch
        # Downloading and saving file to connector
        self.helper.log_info("Importing the file " + file_uri)
        file_name = os.path.basename(file_fetch)
        file_content = self.helper.api.fetch_opencti_file(file_uri, True)
        with open(file_name, "wb") as f:
            f.write(file_content)
        return file_name


if __name__ == "__main__":
    try:
        connectorActorImporter = ActorImporter()
        connectorActorImporter.start()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)

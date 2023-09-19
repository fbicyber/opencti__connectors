import csv
import json
from typing import Dict

# from helper import get_config, get_helper
from models import Group, Individual
from pycti import OpenCTIApiClient, ThreatActorGroup, ThreatActorIndividual
from pydantic import ValidationError


class FileProcessor:
    """
    Consume, validate and ingest an uploaded csv file of OpenCTI/STIX data.
    Returns:
        _type_: _description_
    """

    def __init__(self, config, helper, author) -> None:
        self.config = config
        self.custom_properties = dict()
        self.helper = helper
        self.author = author

        self.api = OpenCTIApiClient(
            config["opencti"]["url"], config["opencti"]["token"]
        )
        self.helper.log_info("Starting File Processor")

    def get_recs(self, file_name: str):
        self.helper.log_info("Getting records")
        recs = dict()
        with open(file_name, newline="", encoding="utf-8-sig") as infile:
            self.helper.log_info(f"Reading records from: {file_name}")
            reader = csv.reader(infile)
            header = next(reader)
            self.helper.log_info(f"Header information: {header}")
            valid_formats = next(reader)
            self.helper.log_info(f"Valid data formats: {valid_formats}")
            # traverse all the rows in the import
            for row_num, row in enumerate(reader):
                # create the entity record
                row_records = {}
                # traverse each col, add to correctly identify entity rec
                for col_num, col in enumerate(row):
                    if (
                        col_num == 0
                    ):  # first col contains 'collection.fieldname' and should be skipped
                        continue
                    entity, item = header[col_num].split(".", 1)
                    entity = entity.title()
                    if col:
                        # value found to be stored
                        if entity not in row_records:
                            # setup the row_records with the entity
                            row_records[entity] = {}
                        if item not in row_records[entity]:
                            # item doesn't exist, create it
                            row_records[entity][item] = []
                        # append item to existing values
                        if type(col) == str:
                            row_records[entity][item] = col
                        elif type(col) == list:
                            row_records[entity][item].extend(col)
                # done processing cols in row
                for k, v in row_records.items():
                    if k not in recs:
                        #  create entity entry in docs
                        recs[k] = []
                    if "id" not in v:
                        v["id"] = ""
                    # store new row records into recs by entity type
                    recs[k].append(v)
            # self.helper.log_info(recs)
            return recs

    def validate_recs(self, recs: Dict):
        self.helper.log_info("Validating records")
        validated_recs = []
        for k, v in recs.items():
            if k == "Threatactorindividual":
                individual = dict()
                for rec in v:
                    msg = ""
                    try:
                        msg += f"\nInitial Threat Actor Individual:\n{json.dumps(rec, indent=4)}\n"
                        validation = Individual(**rec)
                        msg += f"\nValidated Threat Actor Individual(post-pydantic):\n{json.dumps(validation.dict(), indent=4, sort_keys=True, default=str)}\n"
                        # strip out returned null values
                        individual = {k: v for (k, v) in validation.dict().items() if v}
                        self.custom_properties = dict()
                        for key in rec.keys():
                            individual = self.get_custom_attr(
                                data_rec=individual, key=key
                            )
                        msg += f"\nProcessed Threat Actor Individual:\n{json.dumps(individual, indent=4)}\n"
                        msg += f"\nThreat Actor Individual Custom Properties:\n{json.dumps(self.custom_properties, indent=4, sort_keys=True, default=str)}\n"
                        self.helper.log_debug(msg)
                        print(msg)
                    except ValidationError as e:
                        msg += f"\nValidation error:\n{e}\n"
                        msg += f"Threat Actor Individual data record failed to validate: {rec}."
                        self.helper.log_error(msg)
                        print(msg)
                        continue
                    self.custom_properties["createdBy"] = self.author.id
                    individual.update(self.custom_properties)
                    stix2_individual = ThreatActorIndividual(self.api).create(
                        **individual
                    )
                    validated_recs.append(stix2_individual)
            if k == "Threatactorgroup":
                group = dict()
                for rec in v:
                    try:
                        # self.helper.log_debug(
                        print(
                            f"\nInitial Threat Actor Group:\n{json.dumps(rec, indent=4)}\n"
                        )
                        validation = Group(**rec)
                        # self.helper.log_debug(
                        print(
                            f"\nValidated Threat Actor Group(post-pydantic):\n{json.dumps(validation.dict(), indent=4, sort_keys=True, default=str)}\n"
                        )
                        # strip out returned null values
                        group = {k: v for (k, v) in validation.dict().items() if v}
                        self.custom_properties = dict()
                        for key in rec.keys():
                            group = self.get_custom_attr(data_rec=group, key=key)
                        # self.helper.log_debug(
                        print(
                            f"\nProcessed Threat Actor Group:\n{json.dumps(group, indent=4)}\n"
                        )
                        # self.helper.log_debug(
                        print(
                            f"\nThreat Actor Group Custom Properties:\n{json.dumps(self.custom_properties, indent=4, sort_keys=True, default=str)}\n"
                        )
                    except ValidationError as e:
                        self.helper.log_error(f"\nValidation error:\n{e}\n")
                        self.helper.log_error(
                            f"Threat Actor Group data record failed to validate.\n{rec}"
                        )
                        self.helper.log_error(e)
                        self.helper.log_error(rec)
                        continue
                    stix2_organization = ThreatActorGroup(self.api).create(**group)
                    validated_recs.append(stix2_organization)
            # if k == "Relationship":
            #     validated_recs.append(self._relationship_builder(k, v))
        return validated_recs

    def get_custom_attr(self, data_rec, key):
        """
        extract custom attributes (stix extensions), necessary for the stix2 call
        Args:
            data_rec (dict): pydantic processed dictionary
            key (str): specific custom attribute being processed
        Returns:
            dict: cleaned up dictionary
        """
        if key.startswith("x_mcas") or key.startswith("x_opencti"):
            if data_rec and key in data_rec.keys():
                if data_rec[key]:
                    self.custom_properties[key] = data_rec[key]
                del data_rec[key]
        return data_rec

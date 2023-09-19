"""
Contains all supported models and validations
   supported by the ActorImporter Connector
Raises:
    ValueError: _description_
Returns:
    _type_: _description_
"""

import warnings
from datetime import datetime
from enum import Enum
from typing import List, Optional

from pycti import ThreatActorGroup, ThreatActorIndividual
from pydantic import BaseModel, Field, ValidationError, root_validator, validator
from query_graphql import QueryGraphQL

Countries = QueryGraphQL().get_countries()


def get_dict(v):
    value, date_seen = v.split(",")
    date_seen = date_seen.strip()
    date_seen = datetime.strptime(date_seen, "%m-%d-%Y")
    # back to date string
    date_seen = date_seen.strftime("%m-%d-%Y")
    value = int(value) if isinstance(value, str) and value.isdigit() else None
    if value:
        return value, date_seen
    else:
        return None


def split_str(cls, v):
    """
    takes the list of values and returns an array of values without multiple quotes
    Returns:
        value_list (List[str]): list of countries
    """
    value_list = v.split(",")
    # remove multiple quotes
    newlist = [x.strip("[\"'] +") for x in value_list]
    return newlist


def set_confidence(v) -> int:
    confidence = int(v) if isinstance(v, str) and v.isdigit() else None
    if not confidence or confidence < 0 and confidence > 100:
        warnings.warn(
            f"""\n\n\tWARNING: Value '{v}' must be an integer from 0-100."""
            + f"""\n\tConfidence value is set to None."""
        )
        confidence = None
    return confidence


def name_must_be_a_str(name) -> str:
    """
    name value must be a string (not a list value)
    Args:
        name (str | list): name recieved as input value
    Raises:
        ValueError: raised if values does not contain a name value
    Returns:
        str: name value as a string
    """
    try:
        if type(name) == list:
            return name[0]
        elif type(name) == str:
            return name
    except ValidationError as err:
        raise ValueError(f"ERROR: Values must contain a name field.\n {err}")


# def get_identity_id(cls, values):
#     if values and "name" in values.keys() and values["name"]:
#         values["id"] = ThreatActorIndividual.generate_id(name=values["name"])
#         return values
#     else:
#         raise ValueError(f"ERROR: {values['type'].upper()} must contain a name field.")


def capitalize_all_enum_values(cls, values):
    for field, enum_name in {
        # FIX add all enum values
        "x_mcas_ethnicity": "Origin",
        "x_mcas_eye_color": "EyeColor",
        "x_mcas_gender": "Gender",
        "x_mcas_hair_color": "HairColor",
        "x_mcas_marital_status": "MaritalStatus",
        "x_mcas_nationality": "Origin",
    }.items():
        if field in values.keys():
            # title case the value
            values[field] = values[field].title()
            enum_values = QueryGraphQL().get_enums(enum_name=enum_name)
            if values[field] not in enum_values:
                warnings.warn(
                    f"""\n\n\tValue '{values[field]}' is not in the approved values list: {enum_values}"""
                    + f"""\n\tValue '{values[field]}' is removed."""
                )
                values[field] = None
    return values


# class Countries(str):
#     __str__ = QueryGraphQL().get_countries()
#     # print(f"==> {__str__}")


class Height_Tuple(BaseModel):
    height_in: float
    # centimeters: float
    date_seen: datetime

    def __init__(self, height_in: float, date_seen: datetime) -> None:
        super().__init__(height_in=height_in, date_seen=date_seen)


class Weight_Tuple(BaseModel):
    weight_lb: float
    # kilograms: float
    date_seen: datetime

    def __init__(self, weight_lb: float, date_seen: datetime) -> None:
        super().__init__(weight_lb=weight_lb, date_seen=date_seen)


# class Routing_Numbers(BaseModel):
#     routing_identifier: str


class Individual(BaseModel):
    # validation routines ====================================================>
    _set_confidence = validator("confidence", allow_reuse=True, pre=True)(
        set_confidence
    )
    _get_ind_name_from_list = validator("name", allow_reuse=True, pre=True)(
        name_must_be_a_str
    )
    # _get_identity_id = root_validator(allow_reuse=True)(get_identity_id)
    _capitalize_all_enum_values = root_validator(pre=True, allow_reuse=True)(
        capitalize_all_enum_values
    )
    _split_str = validator(
        "roles",
        # @FIX_ME make employer, citizenship, country of residence and place of birth relationships to country
        # "x_mcas_citizenship",
        # "x_mcas_country_of_residence",
        # "x_mcas_employer",
        # "x_opencti_aliases",
        "aliases",
        allow_reuse=True,
        pre=True,
    )(split_str)

    # @validator(
    #     # @FIX_ME make citizenship, country of residence and place of birth relationships to country
    #     # "x_mcas_citizenship",
    #     # "x_mcas_country_of_residence",
    #     # "x_mcas_place_of_birth",
    #     # each_item=True,
    # )
    def check_country_in_list(cls, v):
        country = (
            str(v[0]) if isinstance(v, list) else v if isinstance(v, (str)) else None
        )
        if country not in Countries:
            warnings.warn(
                f"""\n\n\tValue '{country}' is not in the approved Countries list: {Countries}"""
                + f"""\n\tValue '{country}' is set to null on data ingest."""
            )
            country = None
        return country

    # @validator(
    #     "x_mcas_place_of_birth",
    #     pre=True,
    #     allow_reuse=True,
    # )
    # @validator("x_mcas_place_of_birth", pre=True, allow_reuse=True)
    def fix_multiple_quotes(cls, v):
        # remove multiple quotes
        newlist = v.strip("[\"'] +")
        return newlist

    @validator("x_mcas_date_of_birth", pre=True)
    def parse_date(cls, v):
        # takes a string and formats it as a date string
        if v is None:
            return
        if not isinstance(v, (str, datetime)) and len(v) > 0:
            raise ValueError(
                f"\nx_mcas_date_of_birth: {v} -- is not an empty string and not a valid date with the following format: mm/dd/yyyy"
            )
        if isinstance(v, (str)):
            date_obj = datetime.strptime(v, "%m/%d/%Y")
            return date_obj

    @validator("x_mcas_height", pre=True, always=True)
    def set_height_tuple(cls, v):
        if v:
            height_in, date_seen = get_dict(v)
            if height_in:
                return [Height_Tuple(height_in, date_seen)]
            else:
                return None

    @validator("x_mcas_weight", pre=True, always=True)
    def set_weight_tuple(cls, v):
        if v:
            weight_lb, date_seen = get_dict(v)
            if weight_lb:
                return [Weight_Tuple(weight_lb, date_seen)]
            else:
                return None

    # validation above

    # actual model starts here ===============================================>

    # required pre-populated fields
    # id: str  # populated during validation
    # threat_actor_types: Enum = "Threat-Actor-Individual"
    type: str = "threat-actor-individual"

    # order matters, name must come first
    name: Optional[str] = None
    confidence: Optional[int]
    contact_information: Optional[str]
    description: Optional[str] = "Actor Importer Connector - Threat Actor Individual"
    roles: Optional[List[str]] = []

    # x_mcas extensions

    # @FIX_ME make employer, citizenship, country of residence and place of birth relationships to country
    # x_mcas_citizenship: Optional[List[str]] = []  # array of strings
    # x_mcas_country_of_residence: Optional[List[str]] = []  # array of strings
    # x_mcas_place_of_birth: Optional[str] = None
    # x_mcas_employer: Optional[List[str]] = []  # array of strings
    x_mcas_date_of_birth: Optional[datetime] = None  # datetime
    x_mcas_ethnicity: Optional[str] = None  # single enum, optional
    x_mcas_eye_color: Optional[str] = None
    x_mcas_gender: Optional[str] = None
    x_mcas_hair_color: Optional[str] = None
    x_mcas_job_title: Optional[str]
    x_mcas_marital_status: Optional[str] = None
    x_mcas_nationality: Optional[str] = None

    # tuples
    x_mcas_height: Optional[List[Height_Tuple]]
    x_mcas_weight: Optional[List[Weight_Tuple]]

    # x_opencti extensions
    # x_opencti_aliases: Optional[List[str]] = []
    aliases: Optional[List[str]] = []
    x_opencti_firstname: Optional[str]
    x_opencti_lastname: Optional[str]

    # excluded individual fields from connector upload
    #   clientMutationId: str
    #   created: datetime
    #   createdBy: str
    #   externalReferences: [str]
    #   lang: str
    #   modified: datetime
    #   objectLabel: [str]
    #   objectMarking: [str]
    #   revoked: bool
    #   update: bool


class Group(BaseModel):
    # validation routines ====================================================>
    _get_org_name_from_list = validator("name", allow_reuse=True, pre=True)(
        name_must_be_a_str
    )
    # _get_identity_id = root_validator(allow_reuse=True)(get_identity_id)

    _set_confidence = validator("confidence", allow_reuse=True, pre=True)(
        set_confidence
    )
    _split_str = validator(
        # "x_opencti_aliases",
        "aliases",
        "roles",
        allow_reuse=True,
        pre=True,
    )(split_str)

    # validation above

    # actual model starts here ===============================================>

    # required pre-populated fields
    # id: str  # populated during validation
    # threat_actor_types: Enum = "Threat-Actor-Group"
    type: str = "threat-actor-group"

    # order matters, name must come first
    name: Optional[str] = None
    confidence: Optional[int]
    description: Optional[str] = "Actor Importer Connector - Threat Actor Group"
    roles: Optional[List[str]] = []
    aliases: Optional[List[str]] = []

    # x_opencti extensions
    # x_opencti_aliases: Optional[List[str]] = []

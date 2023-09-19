import json

import requests
from helper import get_config


class QueryGraphQL:
    """_summary_

    Returns:history
        _type_: _description_
    """

    def __init__(self) -> None:
        """Initializing the class"""
        self.helper = get_config()
        self.end_point = f"{self.helper['opencti']['url']}/graphql"
        self.headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Connection": "keep-alive",
            "DNT": "1",
            "Origin": self.end_point,
            "Authorization": f"Bearer {self.helper['opencti']['token']}",
        }

    def get_enums(self, enum_name: str) -> list:
        """
        Queries for enums
        Returns:
            list: of enums
        """
        enum_query = """{  __type(name: "%s"){ name  enumValues{ name } } }""" % (
            enum_name
        )
        response = requests.post(
            url=self.end_point,
            headers=self.headers,
            data=json.dumps({"query": enum_query}),
        )
        if response.status_code == 200:
            json_response = json.loads(response.content)
            values = json_response["data"]["__type"]["enumValues"]
            just_values = [n["name"].title() for n in values]
            return just_values
        else:
            self.helper.log_error("{response.status_code}: {response.reason}")

    def get_countries(self) -> list:
        """
        Retrieves list of countries
        Returns:
            list: of countries
        """
        countries_query = """
            {
                countries(first:5000) {
                    edges {
                        node {
                            id
                            standard_id
                            name
                        }
                    }
                }
            }
        """
        response = requests.post(
            url=self.end_point,
            headers=self.headers,
            data=json.dumps({"query": countries_query}),
        )
        if response.status_code == 200:
            json_response = json.loads(response.content)
            if json_response["data"]["countries"] != "None":
                values = json_response["data"]["countries"]["edges"]
                just_values = [n["node"]["name"] for n in values]
                just_values.sort()
                return just_values
            else:
                self.helper.log_warn("No country data returned.")
                return []
        else:
            self.helper.log_error("{response.status_code}: {response.reason}")

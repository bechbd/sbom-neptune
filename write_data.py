import boto3
import json
import logging
from timer import benchmark_timer, Timer


logger = logging.getLogger(__name__)


class NeptuneAnalyticsSBOMWriter:
    client = None
    graph_identifier = None

    def __init__(self, graph_identifier: str, region: str) -> None:
        self.client = boto3.client("neptune-graph", region_name=region)
        self.graph_identifier = graph_identifier

    def write_document(self, bom):
        logging.info("Writing bom metadata")
        parent_component_id = self.write_bom(bom)

        if "components" in bom:
            logging.info("Writing components")
            self.write_components(bom["components"], parent_component_id)
        """if "dependencies" in bom:
            logging.info("Writing dependencies")
            self.write_dependencies(bom["dependencies"], parent_component_id)
        if "vulnerabilities" in bom:
            logging.info("Writing vulnerabilities")
            self.write_vulnerabilities(bom["vulnerabilities"])"""

    def write_bom(self, bom):
        parent_component_id = f"component_{bom['metadata']['component']['name']}"
        self.__write_objects([bom], "document", "serialNumber")
        self.__write_objects([bom["metadata"]], "metadata", "timestamp")
        self.__write_objects([bom["metadata"]["component"]], "component", "name")
        self.__write_rel(
            [
                {
                    "fromId": f"document_{bom['serialNumber']}",
                    "toId": f"metadata_{bom['metadata']['timestamp']}",
                }
            ],
            "DETAILS_ABOUT",
        )
        self.__write_rel(
            [
                {
                    "fromId": f"document_{bom['serialNumber']}",
                    "toId": f"component_{bom['metadata']['component']['name']}",
                }
            ],
            "DETAILS_OF",
        )
        return parent_component_id

    @benchmark_timer
    def write_components(self, components: list, parent_component_id: str):
        timer = Timer()
        timer.start()
        self.__write_objects(components, "component", "name")
        timer.stop()
        part_of_edges = [
            {"fromId": parent_component_id, "toId": f"component_{c['name']}"}
            for c in components
        ]
        logging.info("Writing PART_OF edges")
        timer.start()
        self.__write_rel(part_of_edges, "PART_OF")
        timer.stop()

        logging.info("Writing component -> externalReferences")
        for c in components:
            if "externalReferences" in c:
                self.__write_objects(
                    c["externalReferences"], "externalReference", "url"
                )
                refers_to_edges = [
                    {
                        "fromId": f"component_{c['name']}",
                        "toId": f"externalReference_{r['url']}",
                    }
                    for r in c["externalReferences"]
                ]
                self.__write_rel(refers_to_edges, "REFERS_TO")

    def write_dependencies(self, dependencies: list, parent_component_id: str):
        self.__write_objects(dependencies, "dependency", "ref")
        uses_edges = [
            {"fromId": parent_component_id, "toId": f"dependency_{d['ref']}"}
            for d in dependencies
        ]
        logging.info("Writing USES edges")
        self.__write_rel(uses_edges, "USES")
        for d in dependencies:
            if "dependsOn" in d:
                deps = [{"ref": dep} for dep in d["dependsOn"]]
                self.__write_objects(deps, "dependency", "ref")
                depends_on_edges = [
                    {
                        "fromId": f"dependency_{d['ref']}",
                        "toId": f"dependency_{dep}",
                    }
                    for dep in d["dependsOn"]
                ]
                self.__write_rel(depends_on_edges, "DEPENDS_ON")

    def write_vulnerabilities(self, vulnerabilities: list):
        self.__write_objects(vulnerabilities, "vulnerability", "id")

    def __write_objects(self, objs: object, label: str, keyName: str):
        params = []
        logging.info(f"Writing {label}s")
        if len(objs) == 0:
            return

        query = (
            """
                UNWIND $props as p
                MERGE (s:"""
            + label
            + """ {`~id`: p.__id})
                SET """
            + self.__create_property_map_str(objs[0])
        )
        for o in objs:
            params.append(
                {
                    "__id": f"{label}_{o[keyName]}",
                    **self.__cleanup_map(o),
                }
            )

        self.__execute_query(label, {"props": params}, query)

    def __write_rel(self, rels: list, label: str):
        logging.info(f"Writing {label}s")
        if len(rels) == 0:
            return

        query = (
            """                
                    UNWIND $rels as r
                    MATCH (from {`~id`: r.fromId})
                    MATCH (to {`~id`: r.toId})
                    MERGE (from)-[s:"""
            + label
            + """]->(to) """
        )

        self.__execute_query(label, {"rels": rels}, query)

    def __execute_query(self, label, params, query):
        resp = self.client.execute_open_cypher_query(
            openCypherQuery=query,
            parameters=json.dumps(params),
            graphId=self.graph_identifier,
        )
        if not resp["ResponseMetadata"]["HTTPStatusCode"] == 200:
            print(f"An error occurred saving the {label}.  Query: {query}")

    def __cleanup_map(self, props: dict) -> str:
        """
        This should remove all the lists and dict properties from the map
        """
        result = {}
        for k in props.keys():
            if not isinstance(props[k], list) and not isinstance(props[k], dict):
                result[k] = props[k]
        return result

    def __create_property_map_str(self, props: dict, exclude_list: list = []) -> str:
        """
        This should not be needed but there is a bug in P8 that prevents Maps from working
        """
        result = []
        for k in props.keys():
            if k not in exclude_list:
                if type(props[k]) is None:
                    result.append(f"s.`{k}` = null")
                elif isinstance(props[k], list) or isinstance(props[k], dict):
                    pass
                else:
                    result.append(f"s.`{k}` = p.`{k}`")
        return ",".join(result)

import boto3
import json
import logging
import uuid
from timer import benchmark_timer, Timer
from itertools import islice


logger = logging.getLogger(__name__)
timer = Timer()


class NeptuneAnalyticsSBOMWriter:
    client = None
    graph_identifier = None
    batch_size = 200

    def __init__(self, graph_identifier: str, region: str) -> None:
        self.client = boto3.client("neptune-graph", region_name=region)
        self.graph_identifier = graph_identifier

    def write_document(self, bom):
        logging.info("Writing bom metadata")
        document_id = self.write_bom(bom)

        if "components" in bom:
            logging.info("Writing components")
            self.write_components(bom["components"], document_id)
        if "dependencies" in bom:
            logging.info("Writing dependencies")
            self.write_dependencies(bom["dependencies"], document_id)
        if "vulnerabilities" in bom:
            logging.info("Writing vulnerabilities")
            self.write_vulnerabilities(bom["vulnerabilities"])

    @benchmark_timer
    def write_bom(self, bom):
        document_id = f"document_{uuid.uuid4()}"
        document = {**bom, **bom["metadata"], **bom["metadata"]["component"]}
        self.__write_objects([document], "document", None, id=document_id)

        return document_id

    @benchmark_timer
    def write_components(self, components: list, parent_component_id: str):
        self.__write_objects(components, "component", "name")
        part_of_edges = [
            {"fromId": parent_component_id, "toId": f"component_{c['name']}"}
            for c in components
        ]
        logging.info("Writing PART_OF edges")
        self.__write_rel(part_of_edges, "PART_OF")

        logging.info("Writing component -> externalReferences")
        refs = []
        refers_to_edges = []
        for c in components:
            if "externalReferences" in c:
                # self.__write_objects(
                #    c["externalReferences"], "externalReference", "url"
                # )
                refs.extend(c["externalReferences"])
                refers_to_edges.extend(
                    [
                        {
                            "fromId": f"component_{c['name']}",
                            "toId": f"externalReference_{r['url']}",
                        }
                        for r in c["externalReferences"]
                    ]
                )
        self.__write_objects(refs, "externalReference", "url")
        self.__write_rel(refers_to_edges, "REFERS_TO")

    @benchmark_timer
    def write_dependencies(self, dependencies: list, parent_component_id: str):
        self.__write_objects(dependencies, "dependency", "ref")
        uses_edges = [
            {"fromId": parent_component_id, "toId": f"dependency_{d['ref']}"}
            for d in dependencies
        ]
        logging.info("Writing USES edges")
        self.__write_rel(uses_edges, "USES")
        deps = []
        depends_on_edges = []
        for d in dependencies:
            if "dependsOn" in d:
                deps.extend([{"ref": dep} for dep in d["dependsOn"]])
                depends_on_edges.extend(
                    [
                        {
                            "fromId": f"dependency_{d['ref']}",
                            "toId": f"dependency_{dep}",
                        }
                        for dep in d["dependsOn"]
                    ]
                )

        self.__write_objects(deps, "dependency", "ref")
        self.__write_rel(depends_on_edges, "DEPENDS_ON")

    @benchmark_timer
    def write_vulnerabilities(self, vulnerabilities: list):
        self.__write_objects(vulnerabilities, "vulnerability", "id")
        affects_edges = []
        for v in vulnerabilities:
            for a in v["affects"]:
                affects_edges.append(
                    {
                        "from": v["id"],
                        "to": a["ref"],
                    }
                )
        self.__write_rel_match_on_property(affects_edges, "AFFECTS", "id", "bom-ref")

    def chunk(arr_range, arr_size):
        arr_range = iter(arr_range)
        return iter(lambda: tuple(islice(arr_range, arr_size)), ())

    def __write_objects(
        self,
        objs: object,
        label: str,
        keyName: str,
        create_uuid_if_key_not_exists: bool = False,
        id: str = None,
    ):
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
            if keyName in o:
                params.append(
                    {
                        "__id": f"{label}_{o[keyName]}",
                        **self.__cleanup_map(o),
                    }
                )
            elif create_uuid_if_key_not_exists:
                params.append(
                    {
                        "__id": f"{label}_{uuid.uuid4()}",
                        **self.__cleanup_map(o),
                    }
                )

            elif id:
                params.append(
                    {
                        "__id": id,
                        **self.__cleanup_map(o),
                    }
                )
            else:
                raise AttributeError(
                    f"The object {o} does not contain the key {keyName}"
                )

        arr_range = iter(params)
        chunks = iter(lambda: tuple(islice(arr_range, self.batch_size)), ())
        for chunk in chunks:
            # This should not be needed but due to an issue with duplicate maps we have to guarantee uniqeness
            res = list(map(dict, set(tuple(sorted(sub.items())) for sub in chunk)))

            self.__execute_query(label, {"props": res}, query)

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

        arr_range = iter(rels)
        chunks = iter(lambda: tuple(islice(arr_range, self.batch_size)), ())
        for chunk in chunks:
            # This should not be needed but due to an issue with duplicate maps we have to guarantee uniqeness
            res = list(map(dict, set(tuple(sorted(sub.items())) for sub in chunk)))
            self.__execute_query(label, {"rels": res}, query)

    def __write_rel_match_on_property(
        self, rels: list, label: str, from_property: str, to_property: str
    ):
        logging.info(f"Writing {label}s")
        if len(rels) == 0:
            return

        query = (
            """                
                    UNWIND $rels as r
                    MATCH (from {`"""
            + from_property
            + """`: r.from})
                    MATCH (to {`"""
            + to_property
            + """`: r.to})
                    MERGE (from)-[s:"""
            + label
            + """]->(to) """
        )

        arr_range = iter(rels)
        chunks = iter(lambda: tuple(islice(arr_range, self.batch_size)), ())
        for chunk in chunks:
            # This should not be needed but due to an issue with duplicate maps we have to guarantee uniqeness
            res = list(map(dict, set(tuple(sorted(sub.items())) for sub in chunk)))
            self.__execute_query(label, {"rels": res}, query)

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

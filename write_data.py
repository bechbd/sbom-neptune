import boto3
import json
import logging
import uuid
from timer import benchmark_timer, Timer
from itertools import islice
from enum import Enum


class BomType(Enum):
    CYDX = "cyclonedx"
    SPDX = "spdx"
    UNKNOWN = "unknown"


BATCH_SIZE = 200


logger = logging.getLogger(__name__)
timer = Timer()


class NeptuneAnalyticsSBOMWriter:
    client = None
    graph_identifier = None

    def __init__(self, graph_identifier: str, region: str) -> None:
        self.client = boto3.client("neptune-graph", region_name=region)
        self.graph_identifier = graph_identifier

    def __determine_filetype(self, bom: str):
        if "spdxVersion" in bom:
            print("SPDX")
            return BomType.SPDX
        elif "bomFormat" in bom:
            print("CycloneDX")
            return BomType.CYDX
        else:
            print("Unknown SBOM format")
            return BomType.UNKNOWN

    def write_sbom(self, bom: str):
        bom_type = self.__determine_filetype(bom)
        res = False
        if bom_type == BomType.CYDX:
            res = CycloneDXWriter(self.graph_identifier, self.client).write_document(
                bom
            )
        elif bom_type == BomType.SPDX:
            res = SPDXWriter(self.graph_identifier, self.client).write_document(bom)
        else:
            print("Unknown SBOM format")

        return res


class Writer:
    client = None
    graph_identifier = None
    batch_size = 200

    def __init__(self, graph_identifier: str, client: boto3.client) -> None:
        self.client = client
        self.graph_identifier = graph_identifier

    def chunk(arr_range, arr_size):
        arr_range = iter(arr_range)
        return iter(lambda: tuple(islice(arr_range, arr_size)), ())

    def write_objects(
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

    def write_rel(self, rels: list, label: str):
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

    def write_rel_match_on_property(
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


class CycloneDXWriter(Writer):
    def write_document(self, bom):
        logging.info("Writing bom metadata")
        document_id = self.__write_bom(bom)

        if "components" in bom:
            logging.info("Writing components")
            self.__write_components(bom["components"], document_id)
        if "dependencies" in bom:
            logging.info("Writing dependencies")
            self.__write_dependencies(bom["dependencies"], document_id)
        if "vulnerabilities" in bom:
            logging.info("Writing vulnerabilities")
            self.__write_vulnerabilities(bom["vulnerabilities"])
        return True

    @benchmark_timer
    def __write_bom(self, bom):
        document_id = f"document_{uuid.uuid4()}"
        document = {**bom, **bom["metadata"], **bom["metadata"]["component"]}

        # Do mappings from Cyclone DX to more generic name
        document["spec_version"] = document.pop("specVersion")
        document["created_timestamp"] = document.pop("timestamp")

        self.write_objects([document], "document", None, id=document_id)

        return document_id

    @benchmark_timer
    def __write_components(self, components: list, document_id: str):
        self.write_objects(components, "component", "name")
        describes_edges = [
            {"fromId": document_id, "toId": f"component_{c['name']}"}
            for c in components
        ]
        logging.info("Writing DESCRIBES edges")
        self.write_rel(describes_edges, "DESCRIBES")

        logging.info("Writing component -> externalReferences")
        refs = []
        refers_to_edges = []
        for c in components:
            if "externalReferences" in c:
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
        self.write_objects(refs, "externalReference", "url")
        self.write_rel(refers_to_edges, "REFERS_TO")

    @benchmark_timer
    def __write_dependencies(self, dependencies: list, document_id: str):
        self.write_objects(dependencies, "dependency", "ref")
        uses_edges = [
            {"fromId": document_id, "toId": f"dependency_{d['ref']}"}
            for d in dependencies
        ]
        logging.info("Writing USES edges")
        self.write_rel(uses_edges, "USES")
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

        self.write_objects(deps, "dependency", "ref")
        self.write_rel(depends_on_edges, "DEPENDS_ON")

    @benchmark_timer
    def __write_vulnerabilities(self, vulnerabilities: list):
        self.write_objects(vulnerabilities, "vulnerability", "id")
        affects_edges = []
        for v in vulnerabilities:
            for a in v["affects"]:
                affects_edges.append(
                    {
                        "from": v["id"],
                        "to": a["ref"],
                    }
                )
        self.write_rel_match_on_property(affects_edges, "AFFECTS", "id", "bom-ref")


class SPDXWriter(Writer):
    def write_document(self, bom):
        logging.info("Writing bom metadata")

        document_id = self.__write_bom(bom)

        if "packages" in bom:
            logging.info("Writing packages as components")
            self.__write_packages(bom["packages"], document_id)

        if "relationships" in bom:
            logging.info("Writing relationships")
            self.__write_relationships(bom["relationships"], document_id)

        return True

    @benchmark_timer
    def __write_bom(self, bom):
        document_id = f"document_{uuid.uuid4()}"
        document = {**bom, **bom["creationInfo"]}

        # Do mappings from Cyclone DX to more generic name
        document["specVersion"] = document.pop("spdxVersion")
        document["createdTimestamp"] = document.pop("created")
        document["bomFormat"] = "SPDX"

        self.write_objects([document], "document", None, id=document_id)

        return document_id

    @benchmark_timer
    def __write_packages(self, components: list, document_id: str):
        self.write_objects(components, "component", "name")

        logging.info("Writing component -> externalReferences")
        refs = []
        refers_to_edges = []
        for c in components:
            if "externalRefs" in c:
                refs.extend(c["externalRefs"])
                refers_to_edges.extend(
                    [
                        {
                            "fromId": f"component_{c['name']}",
                            "toId": f"externalReference_{r['referenceLocator']}",
                        }
                        for r in c["externalRefs"]
                    ]
                )
        self.write_objects(refs, "externalReference", "referenceLocator")
        self.write_rel(refers_to_edges, "REFERS_TO")

    @benchmark_timer
    def __write_relationships(self, relationships: list, document_id: str):
        logging.info("Writing DESCRIBES edges")
        describes_edges = []
        for d in relationships:
            describes_edges.append(
                {
                    "to": d["relatedSpdxElement"],
                    "from": document_id,
                }
            )
        self.write_rel_match_on_property(describes_edges, "DESCRIBES", "~id", "SPDXID")

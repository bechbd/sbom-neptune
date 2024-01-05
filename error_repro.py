import boto3
import json

client = boto3.client("neptune-graph", region_name="us-west-2")
graph_identifier = "g-zihygryofa"

# Correctly formatted so this works
resp = client.execute_open_cypher_query(
    openCypherQuery="""
        UNWIND $props as p
        RETURN p
    """,
    parameters=json.dumps({"props": [{"id": "123"}]}),
    graphId=graph_identifier,
)
print(resp)


# Incorrectly formatted so this throws and IFE
resp = client.execute_open_cypher_query(
    openCypherQuery="""
        UNWIND $props as p
        RETURN p
    """,
    parameters=json.dumps([{"id": "123"}]),
    graphId=graph_identifier,
)
print(resp)

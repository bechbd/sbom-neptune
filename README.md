# sbom-neptune

This is (will eventually be) a library that ingests CycloneDX and SPDX files and ingests them into an Existing Neptune Analytics Graph.

## Prerequisties

- Python 3
- A Neptune Analytics Graph
- A pre-release version of the Boto3 Model File

## Installing

From the base directory you first need to install the python requirements

```
pip install -r requirements.txt
```

Next you need to add one or more CycloneDX JSON file(s) into the `/examples/CycloneDX` directory or SPDX files to the `/examples/SPDX` directory

In the `main.py` change this line to be your graph id and region

```
writer = NeptuneAnalyticsSBOMWriter("<Graph ID>", "<AWS Region>")
```

Run the python file: `python3 main.py`

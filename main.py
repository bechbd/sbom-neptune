import json
import os
from write_data import NeptuneAnalyticsSBOMWriter
import logging

logging.basicConfig(level=logging.INFO)


def main():
    writer = NeptuneAnalyticsSBOMWriter("g-eag8ov6zf3", "us-west-2")
    directory = "./test/"
    for f in os.listdir(directory):
        print(f)
        if f.endswith(".json") or f.endswith(".txt"):
            with open(os.path.join(directory, f)) as file:
                data = json.load(file)
                writer.write_sbom(data)


if __name__ == "__main__":
    main()

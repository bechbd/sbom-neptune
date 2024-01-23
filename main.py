import json
import os
from write_data import NeptuneAnalyticsSBOMWriter


def main():
    writer = NeptuneAnalyticsSBOMWriter("g-3zdiljkuw3", "us-west-2")
    directory = "./test/"
    for f in os.listdir(directory):
        if f.endswith(".json") or f.endswith(".txt"):
            with open(os.path.join(directory, f)) as file:
                data = json.load(file)
                writer.write_sbom(data)


if __name__ == "__main__":
    main()

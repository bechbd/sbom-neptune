import json
import os
from write_data import NeptuneAnalyticsSBOMWriter


def main():
    writer = NeptuneAnalyticsSBOMWriter("g-s9dng7po95", "us-west-2")
    directory = "./examples/CycloneDX/"
    for f in os.listdir(directory):
        if f.endswith(".json"):
            with open(os.path.join(directory, f)) as file:
                data = json.load(file)
            writer.write_document(data)


if __name__ == "__main__":
    main()

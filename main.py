import json
from write_data import NeptuneAnalyticsSBOMWriter


def main():
    writer = NeptuneAnalyticsSBOMWriter("g-zihygryofa", "us-west-2")
    with open("./examples/drop-wizard-bom.json") as f:
        data = json.load(f)
    writer.write_document(data)


if __name__ == "__main__":
    main()

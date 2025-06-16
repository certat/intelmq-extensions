#!/bin/python3

import argparse
import json

from intelmq_extensions.cli.utils import merge_harmonization

ADDITIONAL_FILES = ["constituency.harmonization.part.json"]
OUTPUT_FILE = "merged-harmonization.conf"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-f",
        "--file",
        nargs="+",
        default=ADDITIONAL_FILES,
        help="Files to merge into harmonization",
    )
    parser.add_argument(
        "-a",
        "--harmonization",
        default=None,
        help="Harmonization file to merge with, if not the default from intelmq",
    )
    parser.add_argument("-o", "--output", default=OUTPUT_FILE, help="Output file")

    args = parser.parse_args()

    definitions = []
    for file in args.file:
        with open(file) as f:
            definitions.append(json.load(f))

    result = merge_harmonization(definitions, args.harmonization)

    with open(args.output, "w+") as f:
        json.dump(result, f, indent=4)


if __name__ == "__main__":
    main()

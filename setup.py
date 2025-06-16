from pathlib import Path

from setuptools import setup

BASE_REQUIREMENTS = [
    "intelmq",
    "importlib_metadata; python_version < '3.8'",
    # intelmqcli
    "python-termstyle>=0.1.10",
    "tabulate>=0.7.5",
    "psycopg2-binary",
    "rt<3.0.0,>=1.0.9",
    "mergedeep",
    # squelcher
    "netaddr>=0.7.14",
]

TESTS_REQUIRES = [
    "pytest",
    "requests-mock",
    "freezegun",
]


def generate_bots_entry_points():
    groups = ["collectors", "parsers", "experts", "outputs"]
    bots = []
    base_path = Path(__file__).parent / "intelmq_extensions/bots"
    bot_files = [
        bot_file
        for bot_file in Path(base_path).glob("**/*.py")
        if bot_file.is_file() and not bot_file.name.startswith("_")
    ]
    for file in bot_files:
        file = Path(str(file).replace(str(base_path), "intelmq_extensions/bots"))
        module = ".".join(file.with_suffix("").parts)
        bots.append("{0} = {0}:BOT.run".format(module))
        # Incoming IntelMQ extensions entrypoints
        entry_point = None
        for group in groups:
            module_prefix = "intelmq_extensions.bots.{}".format(group)
            if module.startswith(module_prefix):
                entry_point = module.replace(
                    module_prefix, "intelmq.bots.{}.certat".format(group)
                )
        if not entry_point:
            raise ValueError("Unrecognized bot type in {}".format(module))
        bots.append("{0} = {1}:BOT.run".format(entry_point, module))
    return bots


# FIXME: doesn't work for wheel build
def collect_requirements():
    requires = set(BASE_REQUIREMENTS)
    base_path = Path(__file__).parent / "intelmq_extensions/bots"
    bot_requires = [
        bot_file for bot_file in Path(base_path).glob("**/REQUIREMENTS.txt")
    ]

    for file in bot_requires:
        with open(file, "r") as f:
            requires.update(line for line in f.readlines())

    return list(requires)


setup(
    entry_points={
        "console_scripts": [
            "intelmqcli = intelmq_extensions.cli.intelmqcli:main",
            "intelmqcli_create_reports = intelmq_extensions.cli.create_reports:main",
        ]
        + generate_bots_entry_points()
    },
    install_requires=collect_requirements(),
)

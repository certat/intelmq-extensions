from intelmq import HARMONIZATION_CONF_FILE
from intelmq.lib.utils import load_configuration
from mergedeep import merge


def merge_harmonization(
    additional_definitions: list[dict], harmonization_path: str = None
):
    harmonization_path = harmonization_path or HARMONIZATION_CONF_FILE
    harmonization = load_configuration(harmonization_path)

    return merge(*additional_definitions, harmonization)

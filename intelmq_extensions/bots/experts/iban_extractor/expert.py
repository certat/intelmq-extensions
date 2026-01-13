"""
IBAN Extractor looks for IBAN in the given field and extracts
information as extra fields, including a hash of the iban
"""

import hashlib
import re

import schwifty
from intelmq.lib.bot import ExpertBot


class IBANExtractorExpertBot(ExpertBot):
    lookup_field: str = "extra.text"
    default_country: str = "AT"
    # first group has to match potential IBAN
    base_regex: str = r"\b(([A-Z]{2}|)( |)[0-9]{2}[0-9 ]{1,30})\b"

    def init(self):
        self._possible_iban = re.compile(self.base_regex)

    def process(self):
        event = self.receive_message()

        lookup_data = event.get(self.lookup_field)
        if not lookup_data:
            self.logger.info("Lookup data not found in the event.")
            self.send_message(event, path="no_lookup_data", path_permissive=True)
            self.send_message(event, path="not_found", path_permissive=True)
            self.acknowledge_message()
            return

        iban = None
        for match in self._possible_iban.finditer(lookup_data):
            iban_str = match.group(1).strip()
            if iban_str[0] in "0123456789":
                iban_str = self.default_country + iban_str
            try:
                iban = schwifty.IBAN(iban_str)
                break
            except Exception:
                pass

        if not iban:
            self.send_message(event, path="not_found", path_permissive=True)
            self.acknowledge_message()
            return

        event.add("extra.iban", str(iban), overwrite=False)
        event.add(
            "source.geolocation.cc",
            iban.country_code,
            overwrite=False,
            raise_failure=False,
        )
        event.add(
            "extra.bic",
            str(iban.bic) if iban.bic else None,
            overwrite=False,
            raise_failure=False,
        )
        event.add(
            "extra.bank",
            str(iban.bank_short_name) if iban.bank_short_name else None,
            overwrite=False,
            raise_failure=False,
        )
        iban_hash = hashlib.sha256(str(iban).encode()).hexdigest()
        event.add("extra.iban_hash", iban_hash, overwrite=False)

        self.send_message(event)
        self.acknowledge_message()


BOT = IBANExtractorExpertBot

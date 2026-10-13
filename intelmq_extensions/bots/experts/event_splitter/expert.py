"""Event Splitter can produce multiple events from a one, based
on event's tag.

Currently implemented with intention of splitting CVE events.

SPDX-FileCopyrightText: 2023 CERT.at GmbH <https://cert.at/>
SPDX-License-Identifier: AGPL-3.0-or-later
"""

import re

from intelmq.lib.bot import ExpertBot
from intelmq.lib.exceptions import ConfigurationError

KEEP_ORIGINAL_MODES = ("allow", "block")


class EventSplitterExpertBot(ExpertBot):
    look_in: str = "extra.tag"
    copy_to: list[str] = ["classification.identifier", "extra.vulnerabilities"]
    regex: str = ""  # has to match one group meaning matched duplication value

    # determine if we should keep original event even when matches occur
    # by empty matches the event is always kept
    keep_original: bool = False
    # if set, keep original only if the selected field matches the regex
    # requires keep_original and keep_original_look_in
    keep_original_regex: str = ""
    keep_original_look_in: str = ""
    # "allow": keep original if the regex matches
    # "block": keep original only if the regex does not match
    keep_original_mode: str = "allow"

    def init(self):
        errors = self._validate_config(
            {
                "regex": self.regex,
                "keep_original": self.keep_original,
                "keep_original_regex": self.keep_original_regex,
                "keep_original_look_in": self.keep_original_look_in,
                "keep_original_mode": self.keep_original_mode,
            }
        )
        if errors:
            parameter, message = errors[0]
            raise ConfigurationError(message, parameter)

        self.matcher = re.compile(self.regex)
        self.keep_original_matcher = None
        if self.keep_original_regex:
            self.keep_original_matcher = re.compile(self.keep_original_regex)

    @staticmethod
    def _validate_config(parameters: dict) -> list[tuple[str, str]]:
        """Return a list of (parameter, message) for every configuration problem"""
        cls = EventSplitterExpertBot
        regex = parameters.get("regex", cls.regex)
        keep_original = parameters.get("keep_original", cls.keep_original)
        keep_original_regex = parameters.get(
            "keep_original_regex", cls.keep_original_regex
        )
        keep_original_look_in = parameters.get(
            "keep_original_look_in", cls.keep_original_look_in
        )
        keep_original_mode = parameters.get(
            "keep_original_mode", cls.keep_original_mode
        )

        errors = []
        for name, value in (
            ("regex", regex),
            ("keep_original_regex", keep_original_regex),
        ):
            try:
                re.compile(value)
            except (re.error, TypeError) as exc:
                errors.append((name, f"invalid regular expression: {exc}"))

        if keep_original_mode not in KEEP_ORIGINAL_MODES:
            errors.append(
                (
                    "keep_original_mode",
                    f"must be one of: {', '.join(KEEP_ORIGINAL_MODES)}",
                )
            )

        if keep_original_regex:
            if not keep_original:
                errors.append(
                    (
                        "keep_original",
                        "has to be enabled when keep_original_regex is set",
                    )
                )
            if not keep_original_look_in:
                errors.append(
                    (
                        "keep_original_look_in",
                        "has to be set when keep_original_regex is set",
                    )
                )
        else:
            if keep_original_look_in:
                errors.append(
                    (
                        "keep_original_regex",
                        "has to be set when keep_original_look_in is set",
                    )
                )
            if keep_original_mode == "block":
                errors.append(
                    (
                        "keep_original_regex",
                        "has to be set when keep_original_mode is 'block'",
                    )
                )

        return errors

    @staticmethod
    def check(parameters: dict) -> list[list[str]] or None:
        errors = EventSplitterExpertBot._validate_config(parameters)
        return [
            ["error", f"Parameter '{parameter}' {message}."]
            for parameter, message in errors
        ] or None

    def _should_keep_original(self, event) -> bool:
        if not self.keep_original:
            return False
        if not self.keep_original_matcher:
            return True
        value = event.get(self.keep_original_look_in, "")
        matched = bool(self.keep_original_matcher.search(str(value)))
        if self.keep_original_mode == "block":
            return not matched
        return matched

    def process(self):
        event = self.receive_message()

        lookup_data = event.get(self.look_in, "")
        matches = self.matcher.findall(lookup_data)
        if not matches:
            self.send_message(event)
        else:
            if self._should_keep_original(event):
                self.logger.debug("Keeping original event.")
                self.send_message(event)
            for matched in matches:
                self.logger.debug("Found: %s.", matched)
                sub_event = self.new_event(event)
                for key in self.copy_to:
                    sub_event.add(key, matched, overwrite=True)
                self.send_message(sub_event)

        self.acknowledge_message()


BOT = EventSplitterExpertBot

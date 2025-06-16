"""Parsing DISP data feed.

Currently only for credentials tracking

SPDX-FileCopyrightText: 2023 CERT.at GmbH <https://cert.at/>
SPDX-License-Identifier: AGPL-3.0-or-later
"""

import json
from copy import deepcopy
from datetime import datetime
from urllib import parse

import intelmq.lib.message as message
from dateutil.parser import ParserError
from dateutil.parser import parse as dt_parse
from dateutil.tz import UTC
from dns.exception import DNSException
from intelmq.lib import utils
from intelmq.lib.bot import ParserBot
from intelmq.lib.exceptions import IntelMQException
from intelmq.lib.harmonization import URL, DateTime


class InvalidData(IntelMQException, ValueError):
    """Given message is invalid comparing with parser requirements"""


class DISPParserBot(ParserBot):
    compromise_time_format: str = "%Y-%m"  # empty, 'original' or format string
    redact_url_path: bool = True
    resolve_ip: bool = False

    def parse(self, report: message.Report):
        raw_report = utils.base64_decode(report.get("raw"))
        report_data = json.loads(raw_report)

        incident = report_data.get("incident")
        evidences = report_data.get("evidences", {}).get("credentials")

        if not evidences:
            self.logger.error("Report doesn't contain any evidences")
            raise InvalidData("No evidences in DISP report")

        for evidence in evidences:
            current = {"incident": deepcopy(incident), "evidence": evidence}
            self._current_line = json.dumps(current)
            yield current

    def parse_line(self, line: dict, report: message.Report):
        event = self.new_event(report)
        event.add("raw", json.dumps(line))

        incident, evidence = line.get("incident"), line.get("evidence")
        self._map_incident(incident, event)
        self._map_evidence(evidence, event)
        return event

    def _map_incident(self, incident: dict, event: message.Event):
        event.add("event_description.text", incident.get("title"))
        event.add("extra.feed_event_id", incident.get("id"))
        event.add(
            "time.source", DateTime.from_epoch_millis(incident.get("validationDate"))
        )
        event.add("extra.monitored_asset", incident.get("relatedAssets", [""])[0])

    def _map_evidence(self, evidence: dict, event: message.Event):
        url = evidence.get("url")
        parsed_url = parse.urlsplit(url)
        event.add("source.fqdn", parsed_url.netloc)

        if self.resolve_ip:
            try:
                event.add("source.ip", URL.to_ip(url))
            except DNSException:
                self.logger.warning("Cannot get IP for domain %s.", url, exc_info=True)

        path = parsed_url.path
        if self.redact_url_path and parsed_url.path and parsed_url.path != "/":
            path = "/[REDACTED]"
        event.add(
            "source.url",
            f"{parsed_url.scheme}://{parsed_url.netloc}{path}",
            sanitize=True,
        )
        event.add("source.urlpath", path)
        event.add("extra.full_url", self._disarm_url(url))

        event.add("source.account", evidence.get("username"))
        event.add("extra.account", evidence.get("username"))
        event.add("extra.password", evidence.get("password"))
        event.add("extra.application", evidence.get("application"))
        event.add("extra.compromise_time", self._parse_compromise_time(evidence))
        event.add("extra.compromise_time_full", evidence.get("date"))

        event.add("malware.name", evidence.get("malware"))

    @staticmethod
    def _disarm_url(url: str):
        """Prevents URLs being usable"""
        url = url.replace("http://", "hxxp://")
        return url.replace("https://", "hxxps://")

    def _parse_compromise_time(self, evidence: dict):
        compromise_time = evidence.get("date")
        if not compromise_time:
            return None

        if self.compromise_time_format == "original":
            return compromise_time

        if not self.compromise_time_format:
            return ""

        try:
            dt: datetime = dt_parse(compromise_time).astimezone(tz=UTC)
        except ParserError:
            self.logger.warning(
                "Error parsing compromise time %s.", compromise_time, exc_info=True
            )
            return None
        return dt.strftime(self.compromise_time_format)


BOT = DISPParserBot

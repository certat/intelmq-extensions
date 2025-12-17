"""Parsing Modat search requests

Currently supporting only host search results

SPDX-FileCopyrightText: 2025 CERT.at GmbH <https://cert.at/>
SPDX-License-Identifier: AGPL-3.0-or-later
"""

import json
from datetime import datetime, timezone

import intelmq.lib.message as message
from intelmq.lib import utils
from intelmq.lib.bot import ParserBot


class ModatParserBot(ParserBot):
    def parse(self, report: message.Report):
        raw_report = utils.base64_decode(report.get("raw"))
        report_data = json.loads(raw_report)

        for entry in report_data:
            self._current_line = json.dumps(entry)
            yield entry

    def parse_line(self, line: dict, report: message.Report):
        event = self.new_event(report)
        event.add("raw", self._current_line)

        event.add("source.ip", line.get("ip"), raise_failure=False)
        event.add(
            "source.geolocation.cc",
            line.get("geo", {}).get("country_iso_code"),
            raise_failure=False,
        )
        event.add(
            "source.geolocation.country",
            line.get("geo", {}).get("country_name"),
            raise_failure=False,
        )
        event.add(
            "source.geolocation.city",
            line.get("geo", {}).get("city_name"),
            raise_failure=False,
        )

        event.add("source.asn", line.get("asn", {}).get("number"), raise_failure=False)
        event.add("source.as_name", line.get("asn", {}).get("org"), raise_failure=False)
        fqdns = line.get("fqdns", [])
        if fqdns:
            event.add("source.fqdn", fqdns[0], raise_failure=False)
        if len(fqdns) > 1:
            event.add("extra.fqdns", ";".join(fqdns), raise_failure=False)
        event.add("extra.tag", ";".join(line.get("tags", [])), raise_failure=False)

        cves = ";".join(cve.get("id", "").lower() for cve in line.get("cves", []))
        if cves:
            event.add("product.vulnerabilities", cves, raise_failure=False)

        services = line.get("services", [])
        last_scanned = datetime.now(tz=timezone.utc)
        if services:
            last_scanned = max(s["scanned_at"] for s in services)
            event.add("extra.services", services, raise_failure=False)

            for service in services:
                # This is what we were looking for
                if service["is_match"]:
                    event.add(
                        "protocol.application",
                        service.get("protocol"),
                        ignore=(None, "unknown"),
                        raise_failure=False,
                    )
                    event.add(
                        "protocol.transport",
                        service.get("transport"),
                        raise_failure=False,
                    )
                    event.add("source.port", service.get("port"), raise_failure=False)

                    last_scanned = service.get("scanned_at") or last_scanned

                    # TODO: emit more events?
                    break

        event.add("time.source", last_scanned, raise_failure=False)

        return event


BOT = ModatParserBot

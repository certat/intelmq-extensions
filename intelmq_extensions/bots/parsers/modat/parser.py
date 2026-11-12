"""Parsing Modat search requests

Supports results of both host and service search.
The type of each entry is detected automatically.

Service fingerprinting is mapped to:
    protocol.application, protocol.transport, source.port - service details
    product.name, product.version, product.full_name - fingerprinted service product
    product.vulnerabilities - CVEs related to the service
    extra.os_name, extra.os_version - fingerprinted operating system
    extra.technologies - other detected technologies, as name/version
    extra.tag - fingerprinting tags
    extra.service - remaining service details (HTTP, TLS, SSH, TCP, ...)

Parameters:

excluded_fields
    Service fields (dot-separated paths, relative to the service object) not to be
    copied to extra.service, e.g. because of their size.
    Can be a list or a comma-separated string. Defaults to DEFAULT_EXCLUDED_FIELDS.

SPDX-FileCopyrightText: 2025 CERT.at GmbH <https://cert.at/>
SPDX-License-Identifier: AGPL-3.0-or-later
"""

import json
from copy import deepcopy
from datetime import datetime, timezone

import intelmq.lib.message as message
from intelmq.lib import utils
from intelmq.lib.bot import ParserBot

# Big fields: full banners, HTTP content, certificate and SSH key exchange dumps
DEFAULT_EXCLUDED_FIELDS = [
    "banner",
    "banner_hex",
    "http.body",
    "http.headers",
    "http.css_mmh3",
    "http.js_mmh3",
    "tls.raw",
    "ssh.server_key_exchange",
    "ssh.key_exchange",
]

# Mapped to harmonisation fields
SERVICE_MAPPED_FIELDS = (
    "transport",
    "port",
    "protocol",
    "scanned_at",
    "cves",
    "fingerprints",
)


class ModatParserBot(ParserBot):
    excluded_fields: list[str] = DEFAULT_EXCLUDED_FIELDS

    def init(self):
        excluded_fields = self.excluded_fields or []
        if isinstance(excluded_fields, str):
            excluded_fields = excluded_fields.split(",")
        self._excluded_paths = [
            field.strip().split(".") for field in excluded_fields if field.strip()
        ]

    def parse(self, report: message.Report):
        raw_report = utils.base64_decode(report.get("raw"))
        report_data = json.loads(raw_report)

        for entry in report_data:
            self._current_line = json.dumps(entry)
            yield entry

    def parse_line(self, line: dict, report: message.Report):
        event = self.new_event(report)
        event.add("raw", self._current_line)

        self._parse_common(line, event)
        if isinstance(line.get("service"), dict):
            self._parse_service(line, event)
        else:
            self._parse_host(line, event)

        return event

    @staticmethod
    def _parse_common(line: dict, event: message.Event):
        """Fields shared by host and service results"""
        geo = line.get("geo") or {}
        asn = line.get("asn") or {}

        event.add("source.ip", line.get("ip"), raise_failure=False)
        event.add(
            "source.geolocation.cc",
            geo.get("country_iso_code"),
            raise_failure=False,
        )
        event.add(
            "source.geolocation.country",
            geo.get("country_name"),
            raise_failure=False,
        )
        event.add(
            "source.geolocation.city",
            geo.get("city_name"),
            raise_failure=False,
        )

        event.add("source.asn", asn.get("number"), raise_failure=False)
        event.add("source.as_name", asn.get("org"), raise_failure=False)
        fqdns = line.get("fqdns", [])
        if fqdns:
            event.add("source.fqdn", fqdns[0], raise_failure=False)
        if len(fqdns) > 1:
            event.add("extra.fqdns", ";".join(fqdns), raise_failure=False)

    @staticmethod
    def _add_cves(cves: list, event: message.Event):
        cves = ";".join(cve.get("id", "").lower() for cve in cves)
        if cves:
            event.add("product.vulnerabilities", cves, raise_failure=False)

    def _parse_host(self, line: dict, event: message.Event):
        event.add("extra.tag", ";".join(line.get("tags", [])), raise_failure=False)
        self._add_cves(line.get("cves", []), event)

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

    def _parse_service(self, line: dict, event: message.Event):
        service = line["service"]

        rdns = line.get("rdns", [])
        if rdns:
            event.add("source.reverse_dns", rdns[0], raise_failure=False)
        if len(rdns) > 1:
            event.add("extra.rdns", ";".join(rdns), raise_failure=False)

        event.add(
            "protocol.application",
            service.get("protocol"),
            ignore=(None, "unknown"),
            raise_failure=False,
        )
        event.add("protocol.transport", service.get("transport"), raise_failure=False)
        event.add("source.port", service.get("port"), raise_failure=False)
        event.add(
            "time.source",
            service.get("scanned_at") or datetime.now(tz=timezone.utc),
            raise_failure=False,
        )
        self._add_cves(service.get("cves", []), event)

        self._parse_fingerprints(service, event)
        self._parse_service_details(service, event)

    @staticmethod
    def _parse_fingerprints(service: dict, event: message.Event):
        fingerprints = service.get("fingerprints") or {}

        product = fingerprints.get("service") or {}
        product_name = (product.get("product") or "").strip()
        product_version = (product.get("version") or "").strip()
        if product_name:
            # CPE-like format: lowercase (ensured by the harmonisation), no spaces
            event.add(
                "product.name", "_".join(product_name.split()), raise_failure=False
            )
            event.add("product.version", product_version, raise_failure=False)
            event.add(
                "product.full_name",
                " ".join(filter(None, (product_name, product_version))),
                raise_failure=False,
            )

        os_fingerprint = fingerprints.get("os") or {}
        event.add("extra.os_name", os_fingerprint.get("product"), raise_failure=False)
        event.add(
            "extra.os_version", os_fingerprint.get("version"), raise_failure=False
        )

        technologies = [
            "/".join(filter(None, (tech.get("name"), tech.get("version"))))
            for tech in fingerprints.get("technologies", [])
            if tech.get("name")
        ]
        if technologies:
            event.add("extra.technologies", ";".join(technologies), raise_failure=False)

        event.add(
            "extra.tag", ";".join(fingerprints.get("tags", [])), raise_failure=False
        )

    def _parse_service_details(self, service: dict, event: message.Event):
        """Remaining service details (HTTP, TLS, SSH, ...) without excluded fields

        Fields already mapped to the harmonisation are always skipped,
        the full data stays in raw.
        """
        details = {
            key: deepcopy(value)
            for key, value in service.items()
            if key not in SERVICE_MAPPED_FIELDS
        }
        for path in self._excluded_paths:
            self._remove_path(details, path)
        details = self._drop_empty(details)
        if details:
            event.add("extra.service", details, raise_failure=False)

    @classmethod
    def _remove_path(cls, data, path: list[str]):
        """Remove a nested key, descending into dicts and lists of dicts"""
        if isinstance(data, list):
            for item in data:
                cls._remove_path(item, path)
            return
        if not isinstance(data, dict) or path[0] not in data:
            return
        if len(path) == 1:
            del data[path[0]]
        else:
            cls._remove_path(data[path[0]], path[1:])

    @classmethod
    def _drop_empty(cls, data):
        """Remove None values and empty containers, also left after exclusion"""
        if isinstance(data, dict):
            data = {key: cls._drop_empty(value) for key, value in data.items()}
            return {
                key: value
                for key, value in data.items()
                if value is not None and value not in ({}, [], "")
            }
        if isinstance(data, list):
            return [cls._drop_empty(item) for item in data]
        return data


BOT = ModatParserBot

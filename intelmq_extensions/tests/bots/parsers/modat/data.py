"""Data for tests for ModatParserBot

SPDX-FileCopyrightText: 2025 CERT.at GmbH <https://cert.at/>
SPDX-License-Identifier: AGPL-3.0-or-later
"""

RESPONSE_1 = [
    {
        "ip": "127.0.0.1",
        "geo": {
            "city_name": "Vienna",
            "country_name": "Austria",
            "country_iso_code": "AT",
        },
        "asn": {"number": 8412, "org": "T-Mobile Austria GmbH"},
        "fqdns": ["domain.example.at", "device-123.example.at"],
        "is_anycast": False,
        "tags": [],
        "cves": [
            {"id": "CVE-2020-11985", "cvss": 5.3, "is_kev": False},
            {"id": "CVE-2025-3891", "cvss": 7.5, "is_kev": False},
        ],
        "services": [
            {
                "transport": "tcp",
                "port": 8443,
                "ports": [8443],
                "last_scanned_port": 8443,
                "protocol": "http",
                "scanned_at": "2025-12-17T03:57:49Z",
                "is_match": False,
            },
            {
                "transport": "tcp",
                "port": 49592,
                "ports": [49592],
                "last_scanned_port": 49592,
                "protocol": "http",
                "scanned_at": "2025-05-29T20:24:10.308508Z",
                "is_match": True,
            },
            {
                "transport": "tcp",
                "port": 39895,
                "ports": [39895],
                "last_scanned_port": 39895,
                "protocol": "unknown",
                "scanned_at": "2025-11-22T12:22:14Z",
                "is_match": True,
            },
        ],
    },
    {
        "ip": "127.0.0.2",
        "geo": {
            "city_name": "Feldkirch",
            "country_name": "Austria",
            "country_iso_code": "AT",
        },
        "asn": {"number": 5385, "org": "Russmedia IT GmbH"},
        "fqdns": [],
        "is_anycast": False,
        "tags": [],
        "cves": [
            {"id": "CVE-2016-1247", "cvss": 7.8, "is_kev": False},
            {"id": "CVE-2017-20005", "cvss": 9.8, "is_kev": False},
        ],
        "services": [
            {
                "transport": "tcp",
                "port": 44302,
                "ports": [44302],
                "last_scanned_port": 44302,
                "protocol": "unknown",
                "scanned_at": "2025-11-24T00:30:40Z",
                "is_match": True,
            },
            {
                "transport": "tcp",
                "port": 443,
                "ports": [443],
                "last_scanned_port": 443,
                "protocol": "http",
                "scanned_at": "2025-12-15T15:54:24Z",
                "is_match": False,
            },
            {
                "transport": "tcp",
                "port": 8443,
                "ports": [8443],
                "last_scanned_port": 8443,
                "protocol": "http",
                "scanned_at": "2025-12-16T22:49:47Z",
                "is_match": False,
            },
        ],
    },
]

EVENT_1 = {
    # "raw": RESPONSE1[0],
    "source.ip": "127.0.0.1",
    "source.geolocation.cc": "AT",
    "source.geolocation.country": "Austria",
    "source.geolocation.city": "Vienna",
    "extra": {
        "services": RESPONSE_1[0]["services"],
        "fqdns": "domain.example.at;device-123.example.at",
    },
    "product.vulnerabilities": "cve-2020-11985;cve-2025-3891",
    "protocol.application": "http",
    "protocol.transport": "tcp",
    "source.as_name": "T-Mobile Austria GmbH",
    "source.asn": 8412,
    "source.fqdn": "domain.example.at",
    "source.port": 49592,
    "time.source": "2025-05-29T20:24:10.308508+00:00",
}

EVENT_2 = {
    # "raw": RESPONSE1[1],
    "source.ip": "127.0.0.2",
    "source.geolocation.cc": "AT",
    "source.geolocation.country": "Austria",
    "source.geolocation.city": "Feldkirch",
    "extra": {
        "services": RESPONSE_1[1]["services"],
    },
    "product.vulnerabilities": "cve-2016-1247;cve-2017-20005",
    "protocol.transport": "tcp",
    "source.as_name": "Russmedia IT GmbH",
    "source.asn": 5385,
    "source.port": 44302,
    "time.source": "2025-11-24T00:30:40+00:00",
}

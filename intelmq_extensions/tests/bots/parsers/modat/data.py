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

SERVICE_RESPONSE_1 = [
    {
        "ip": "127.0.0.3",
        "service": {
            "transport": "tcp",
            "port": 22,
            "banner": "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5",
            "banner_hex": "5353482d322e30",
            "banner_sha256": "9370b66484d7",
            "protocol": "ssh",
            "http": None,
            "ssh": {
                "hassh": "1a569b9923ea",
                "server_id": "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5",
                "key_exchange": {
                    "server_host_key": {
                        "algorithm": "ssh-ed25519",
                        "fingerprint_sha256": "5693912237c0",
                    }
                },
            },
            "tcp": {"window_size": 64240},
            "tls": None,
            "scanned_at": "2026-11-01T08:15:42Z",
            "discovered_at": "2026-03-14T09:26:53Z",
            "fingerprints": {
                "os": {"product": "Ubuntu", "version": "24.04"},
                "service": {"product": "OpenSSH", "version": "9.6p1"},
                "technologies": [],
                "tags": ["Remote Access"],
            },
            "cves": [
                {"id": "CVE-2024-6387", "cvss": 8.1, "is_kev": False},
            ],
        },
        "fqdns": ["ssh.example.at"],
        "rdns": ["host-3.example.at"],
        "asn": {"number": 64496, "org": "Example Networks", "netblock": "127.0.0.0/24"},
        "geo": {
            "city_name": "Vienna",
            "country_name": "Austria",
            "country_iso_code": "AT",
        },
        "is_anycast": False,
    },
    {
        "ip": "127.0.0.4",
        "service": {
            "transport": "tcp",
            "port": 443,
            "banner": "HTTP/1.1 200 OK\r\nServer: Apache HTTP Server/2.4.58\r\n",
            "protocol": "http",
            "http": {
                "title": "Example Domain",
                "status_code": 200,
                "body": "<html><title>Example Domain</title></html>",
                "headers": "HTTP/1.1 200 OK\r\nServer: Apache HTTP Server/2.4.58\r\n",
                "files": [
                    {
                        "path": "favicon.ico",
                        "category": "favicon",
                        "sha256": "6478f183c80c",
                    }
                ],
            },
            "ssh": None,
            "tls": {
                "is_self_signed": False,
                "is_trusted": True,
                "is_valid": True,
                "expires_at": "2027-01-15T23:59:59Z",
                "supported_versions": ["TLSv1.2", "TLSv1.3"],
                "fingerprint_sha256": "8f5d3efc29c1",
                "jarm": "27d40d40d29d",
                "issuer": {"common_name": ["Example TLS CA"]},
                "subject": {"common_name": ["www.example.at"]},
                "raw": "Certificate:\n    Data: ...",
            },
            "scanned_at": "2026-11-02T10:00:00Z",
            "fingerprints": {
                "os": None,
                "service": {"product": "Apache HTTP Server", "version": "2.4.58"},
                "technologies": [
                    {"name": "PHP", "version": "8.2.1"},
                    {"name": "jQuery", "version": None},
                ],
                "tags": [],
            },
            "cves": [
                {"id": "CVE-2024-38476", "cvss": 9.8, "is_kev": False},
                {"id": "CVE-2024-38474", "cvss": 9.8, "is_kev": False},
            ],
        },
        "fqdns": [],
        "rdns": [],
        "asn": {"number": 64497, "org": "Other Networks"},
        "geo": None,
        "is_anycast": False,
    },
    {
        "ip": "127.0.0.5",
        "service": {
            "transport": "udp",
            "port": 12345,
            "protocol": "unknown",
            "scanned_at": "2026-11-03T12:00:00Z",
            "fingerprints": None,
            "cves": [],
        },
        "fqdns": [],
        "rdns": [],
        "asn": None,
        "geo": None,
        "is_anycast": False,
    },
]

SERVICE_EVENT_1 = {
    "source.ip": "127.0.0.3",
    "source.geolocation.cc": "AT",
    "source.geolocation.country": "Austria",
    "source.geolocation.city": "Vienna",
    "source.as_name": "Example Networks",
    "source.asn": 64496,
    "source.fqdn": "ssh.example.at",
    "source.reverse_dns": "host-3.example.at",
    "source.port": 22,
    "protocol.application": "ssh",
    "protocol.transport": "tcp",
    "product.name": "openssh",
    "product.version": "9.6p1",
    "product.full_name": "OpenSSH 9.6p1",
    "product.vulnerabilities": "cve-2024-6387",
    "time.source": "2026-11-01T08:15:42+00:00",
    "extra": {
        "os_name": "Ubuntu",
        "os_version": "24.04",
        "tag": "Remote Access",
        "service": {
            "banner_sha256": "9370b66484d7",
            "ssh": {
                "hassh": "1a569b9923ea",
                "server_id": "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5",
            },
            "tcp": {"window_size": 64240},
            "discovered_at": "2026-03-14T09:26:53Z",
        },
    },
}

SERVICE_EVENT_2 = {
    "source.ip": "127.0.0.4",
    "source.as_name": "Other Networks",
    "source.asn": 64497,
    "source.port": 443,
    "protocol.application": "http",
    "protocol.transport": "tcp",
    "product.name": "apache_http_server",
    "product.version": "2.4.58",
    "product.full_name": "Apache HTTP Server 2.4.58",
    "product.vulnerabilities": "cve-2024-38476;cve-2024-38474",
    "time.source": "2026-11-02T10:00:00+00:00",
    "extra": {
        "technologies": "PHP/8.2.1;jQuery",
        "service": {
            "http": {
                "title": "Example Domain",
                "status_code": 200,
                "files": [
                    {
                        "path": "favicon.ico",
                        "category": "favicon",
                        "sha256": "6478f183c80c",
                    }
                ],
            },
            "tls": {
                "is_self_signed": False,
                "is_trusted": True,
                "is_valid": True,
                "expires_at": "2027-01-15T23:59:59Z",
                "supported_versions": ["TLSv1.2", "TLSv1.3"],
                "fingerprint_sha256": "8f5d3efc29c1",
                "jarm": "27d40d40d29d",
                "issuer": {"common_name": ["Example TLS CA"]},
                "subject": {"common_name": ["www.example.at"]},
            },
        },
    },
}

SERVICE_EVENT_3 = {
    "source.ip": "127.0.0.5",
    "source.port": 12345,
    "protocol.transport": "udp",
    "time.source": "2026-11-03T12:00:00+00:00",
}

"""Test data for parser tests. Extracted for readiness

SPDX-FileCopyrightText: 2023 CERT.at GmbH <https://cert.at/>
SPDX-License-Identifier: AGPL-3.0-or-later
"""

DEFAULT_COMPANY = {
    "CompanyId": 1,
    "CompanyName": "Austrian National CERT",
    "DomainName": "cert.at",
}

PATCH_MANAGEMENT = {
    "FindingId": 1,
    "Status": "Active",
    "Severity": "Critical",
    "ControlId": "PATCH-001",
    "Domain": "example.cert.at",
    "IpAddress": "127.0.0.1",
    "ProductName": "openssh_/5.9",
    "Cpes": [
        "cpe:2.3:a:openbsd:openssh:7.6:p1:*:*:*:*:*:*",
        "cpe:2.3:a:openbsd:openssh:7.6:-:*:*:*:*:*:*",
    ],
    "PublishDate": "2023-08-02T07:30:44.38",
    "CvssScore": 9.8,
    "CwssScore": None,
    "CveId": "CVE-2023-38408",
    "CweId": "CWE-428",
    "Detail": (
        "The PKCS#11 feature in ssh-agent in OpenSSH before 9.3p2 has an insufficiently "
        "trustworthy search path, leading to remote code execution if an agent is forwarded "
        "to an attacker-controlled system. (Code in /usr/lib is not necessarily safe for "
        "loading into ssh-agent.) NOTE: this issue exists because of an incomplete fix for"
        " CVE-2016-10009."
    ),
    "References": ["https://nvd.nist.gov/vuln/detail/CVE-2023-38408"],
    "FindingDate": "2023-08-28T13:37:22.717",
    "LastCheckDate": "2023-10-03T11:48:54.257",
    "Ticket": None,
}

APPLICATION_SECURITY = {
    "FindingId": 658443,
    "Status": "Active",
    "Severity": "Critical",
    "ControlId": "APPSEC-014",
    "Domain": "example.cert.at",
    "Output": "Failed",
    "Title": "Cleartext Transmission of Sensitive Information",
    "Detail": "Not encrypted communication on xxx.",
    "FindingDate": "2023-08-28T13:37:22.717",
    "LastCheckDate": "2023-10-03T11:48:58.937",
    "Ticket": None,
}

CREDENTIAL_MANAGEMENT = {
    "FindingId": 44823698,
    "Status": "Active",
    "Severity": "Low",
    "ControlId": "LEAK-003",
    "Domain": "cert.at",
    "EmailorUsername": "user@example.cert.at",
    "Source": "cert_com_leak",
    "LeakDate": "2022-09-22T00:00:00",
    "LeakInfo": "****",
    "PasswordType": "PLAIN",
    "Ticket": None,
}

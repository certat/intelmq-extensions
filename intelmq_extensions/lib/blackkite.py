"""Common parts of BlackKite integration

SPDX-FileCopyrightText: 2023 CERT.at GmbH <https://cert.at/>
SPDX-License-Identifier: AGPL-3.0-or-later
"""

from enum import Enum


class Category(str, Enum):
    ApplicationSecurity = "APPSEC"
    PatchManagement = "PATCH"
    DNSHealth = "DNS"
    EmailSecurity = "SMTP"
    FraudulentDomains = "FRADOM"
    CredentialManagement = "LEAK"
    IPReputation = "REP"
    NetworkSecurity = "NETSEC"
    CDNSecurity = "CDN"
    DDoSResiliency = "DDOS"
    AttackSurface = "ATTSRF"
    SSLTLSstrength = "SSL"
    FraudulentApps = "FRAAPP"
    InformationDisclosure = "INFDIS"
    HacktivistShares = "HACK"
    SocialNetwork = "SOCIAL"
    BrandMonitoring = "BRM"
    WebRanking = "WBR"
    WebsiteSecurity = "WSS"

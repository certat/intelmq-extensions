"""Collector for Deloitte Intelligence Service Portal

SPDX-FileCopyrightText: 2023 CERT.at GmbH <https://cert.at/>
SPDX-License-Identifier: AGPL-3.0-or-later

Connects to the DISP portal and collects selected type of incidents
for every monitored company. Currently, we are prepared for the credential tracing
only.

Parameters:
api_url
auth_token
oauth_clientid
oauth_clientsecret
ouath_url

mark_as_read
wait_for_evidences
mask_password # hardcoded to true
"""

import json
from datetime import datetime, timedelta

from intelmq.lib.bot import CollectorBot
from intelmq.lib.utils import create_request_session, parse_relative

from ._client import DISPClient


class DISPCollectorBot(CollectorBot):
    api_url: str = ""
    auth_token: str = ""
    oauth_clientid: str = ""
    oauth_clientsecret: str = ""
    ouath_url: str = ""
    # refresh access token when it's less than 10 minutes to expire
    refresh_token_before: int = 10

    mark_as_read: bool = False
    wait_for_evidences: bool = True
    not_older_than: str = "7 days"
    # mask_password: bool = True  # hardcoded to true

    def init(self):
        self.set_request_parameters()
        self.session = create_request_session(self)
        self.client = DISPClient(
            api_url=self.api_url,
            auth_token=self.auth_token,
            oauth_clientid=self.oauth_clientid,
            oauth_clientsecret=self.oauth_clientsecret,
            oauth_url=self.ouath_url,
            session=self.session,
            refresh_before=self.refresh_token_before,
            logger=self.logger,
        )

    @staticmethod
    def _mask_passwords(data):
        """Ensure passwords will never be processed nor stored in our systems"""
        for credentials in data.get("credentials", []):
            password = credentials.get("password")
            if not password:
                continue
            if len(password) <= 3:
                mask = "*" * len(password)
            else:
                mask = f"{password[:3]}{'*' * (len(password) - 3)}"
            credentials["password"] = mask

    def process(self):
        after = datetime.utcnow() - timedelta(
            minutes=parse_relative(self.not_older_than)
        )
        for incident in self.client.incidents(after=after, only_unread=True):
            evidences = incident.get("evidences", [])
            expected_file = f'{incident["id"]}.json.txt'
            evidence_file = next(
                filter(lambda f: f.get("name") == expected_file, evidences), None
            )
            if self.wait_for_evidences and not evidence_file:
                self.logger.debug(
                    "Incident %s doesn't have an evidence file yet.", incident.get("id")
                )
                continue

            evidence_data = None
            if evidence_file:
                evidence_data = self.client.download_evidence_json(
                    incident.get("id"), evidence_file.get("idStoredFile")
                )
                self._mask_passwords(evidence_data)

            report = self.new_report()
            report.add(
                "raw", json.dumps({"incident": incident, "evidences": evidence_data})
            )
            self.send_message(report)
            if self.mark_as_read:
                self.client.mark_incident_read(incident.get("id"))


BOT = DISPCollectorBot

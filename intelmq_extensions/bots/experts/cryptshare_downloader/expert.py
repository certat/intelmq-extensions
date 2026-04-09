"""
Cryptshare Downloader allows downloading data from Cryptshare instances.

Note: This bot is currently based on a bit hacky workflow:
1) rt_collector:
    a) extracts URL from the email notifications
    b) opens the URL and packs the input into raw report
    c) the extra.file_name gets the filename, including the downloading ID
2) cryptshare downloader:
    a) knows the password and the Cryptshare URL
    b) extracts ID from the extra.file_name
    c) produces new Report message for each file downloaded from Cryptshare with
       updated extra.file_name and the content as raw for further processing

This expert expects an Report message and returns a Report.

TODO: generalized support in other workflows

Cryptshare: https://www.pointsharp.com/en/products/cryptshare
Cryptshare REST API: https://documentation.cryptshare.com/w/RESTAPI:Swagger_UI_Documentation

SPDX-FileCopyrightText: 2026 CERT.at GmbH <https://cert.at/>
SPDX-License-Identifier: AGPL-3.0-or-later
"""

import re
import secrets
from urllib.parse import parse_qs, urlsplit

from intelmq.lib.bot import ExpertBot
from intelmq.lib.message import Report
from intelmq.lib.utils import create_request_session

CLIENT_IDENTIFICATION = "IntelMQCryptshareDownloader"


class CryptshareDownloadExpertBot(ExpertBot):
    # Example: download;jsessionid=node0aaaaaaaaaa.node0?0&id=rvaaaaaaaa
    lookup_field: str = "extra.file_name"
    cryptshare_url: str = "https://cryptshare.cert.at/"
    password: str = "Test123456789"
    http_user_agent: str = f"{CLIENT_IDENTIFICATION}/1.0"

    client_id: str = None

    @staticmethod
    def _is_client_id_valid(client_id: str):
        return re.search(r"^[a-zA-Z0-9]+$", client_id) is not None

    # TODO: implement check(...)

    def init(self):
        # ClientID is the "secret" identification, but in case of downloading
        # data id does not poses any special role
        if not self.client_id:
            self.client_id = f"{CLIENT_IDENTIFICATION}{secrets.token_hex(20)}"
        if not self._is_client_id_valid(self.client_id):
            raise ValueError(
                "Client id does not match the expected ^[a-zA-Z0-9]+$ regex."
            )

        self.set_request_parameters()
        self.http_header = {
            "X-CS-ClientId": self.client_id,
            "X-CS-Password": self.password,
            # Required constants
            "X-CS-ProductKey": "api.rest",
            "X-CS-MajorApiVersion": "1",
            "X-CS-MinimumMinorApiVersion": "15",
        }
        self.cryptshare_url = self.cryptshare_url.rstrip("/")

    def _extract_transfer_id(self, file_name: str) -> str:
        """Extract the transfer id from the value stored in extra.file_name.

        The rt_collector stores the original link from the website name which looks like:

            download;jsessionid=node0aaaaaaaaaa.node0?0&id=rvaaaaaaaa
        """
        # urlsplit handles values with or without a leading scheme/host
        query = urlsplit(file_name).query or file_name.partition("?")[2]
        params = parse_qs(query)
        ids = params.get("id")
        if not ids:
            raise ValueError(
                f"Cannot extract Cryptshare transfer id from {file_name!r}."
            )
        return ids[0]

    def _get_transfer_files(self, transfer_id: str) -> list:
        """Return the list of files available in the given transfer."""
        response = self.http_session.get(
            f"{self.cryptshare_url}/api/transfers/{transfer_id}/files"
        )
        self.logger.debug("Cryptshare response: %s.", response.text)
        response.raise_for_status()
        return response.json().get("data", [])

    def _download_file(self, transfer_id: str, file_id: str) -> bytes:
        """Download a single file from a Cryptshare transfer."""
        response = self.http_session.get(
            f"{self.cryptshare_url}/api/transfers/{transfer_id}/files/{file_id}",
            stream=True,
        )
        response.raise_for_status()
        return response.content

    def process(self):
        report = self.receive_message()

        file_name = report.get(self.lookup_field)
        if not file_name:
            self.logger.warning(
                "Received report without %s, skipping.", self.lookup_field
            )
            self.acknowledge_message()
            return

        try:
            transfer_id = self._extract_transfer_id(file_name)
        except ValueError as exc:
            self.logger.error("%s", exc)
            self.acknowledge_message()
            return

        # Intentionally refreshing on processing each report
        self.http_session = create_request_session(self)

        self.logger.debug("Fetching Cryptshare transfer %s.", transfer_id)
        files = self._get_transfer_files(transfer_id)

        if not files:
            self.logger.warning(
                "Cryptshare transfer %s does not contain any files.", transfer_id
            )
            self.acknowledge_message()
            return

        for file_info in files:
            file_id = file_info.get("id")
            real_name = file_info.get("fileName")
            if not file_id:
                self.logger.warning(
                    "Skipping file without id in transfer %s: %r.",
                    transfer_id,
                    file_info,
                )
                continue

            self.logger.debug(
                "Downloading file %s (%s) from transfer %s.",
                real_name,
                file_id,
                transfer_id,
            )
            content = self._download_file(transfer_id, file_id)

            # Build a new Report based on the original one so feed.* and other
            # metadata stay attached, then overwrite raw and extra.file_name
            # with the data of the actual downloaded file.
            new_report = Report(report)
            new_report.add("raw", content, overwrite=True)
            new_report.add("extra.cryptshare_id", transfer_id)
            if real_name:
                new_report.add("extra.file_name", real_name, overwrite=True)

            self.send_message(new_report)

        self.acknowledge_message()


BOT = CryptshareDownloadExpertBot

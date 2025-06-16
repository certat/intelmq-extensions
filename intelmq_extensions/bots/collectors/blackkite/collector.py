"""Collector of data from BlackKite API

SPDX-FileCopyrightText: 2023 CERT.at GmbH <https://cert.at/>
SPDX-License-Identifier: AGPL-3.0-or-later

Parameters:

url
client_id
client_secret
refresh_before

categories (dict):
    {category-code, e.g. PATCH}:
        severities: [{list of names}] (optional, override)
        outputs: [{list of names}] (optional, override)
        statuses: [{list of names}] (optional, override)
        include: [{list of ids, eg. XXX-001}] (optional, mutual exclusive with exclude)
        exclude: [{list of ids, eg. XXX-001}] (optional, mutual exclusive with include)
        acknowledge: bool (optional, whether change finding's status to acknowledged or not
                     (default: false))
severities: []{list of names}
outputs: [{list of names}]
statuses: [{list of names}]
"""

import json

from intelmq.lib.bot import CollectorBot
from intelmq.lib.utils import create_request_session

from intelmq_extensions.lib.blackkite import Category

from ._client import CATEGORIES_WITH_OUTPUT, BlackKiteClient, Output, Severity, Status


class BlackKiteCollectorBot(CollectorBot):
    url: str = ""
    client_id: str = ""
    client_secret: str = ""
    # refresh access token when it's less than 10 minutes to expire
    refresh_token_before: int = 10
    # BlackKite has API rate limit 60 req./1 minute
    limit_requests: int = 60
    limit_period: int = 60  # 1 minute
    page_size: int = 100

    categories: dict = {}
    severities: list = [Severity.CRITICAL.value]
    outputs: list = [Output.FAILED.value]
    statuses: list = [Status.ACTIVE.value]

    def init(self):
        self.set_request_parameters()
        self.session = create_request_session(self)
        self.client = BlackKiteClient(
            url=self.url,
            client_id=self.client_id,
            client_secret=self.client_secret,
            refresh_before=self.refresh_token_before,
            session=self.session,
            logger=self.logger,
            limit_requests=self.limit_requests,
            limit_period=self.limit_period,
            page_size=self.page_size,
        )

        self._process_settings()

    def _process_settings(self):
        self._default_config = {
            "severities": [Severity(value) for value in self.severities],
            "outputs": [Output(value) for value in self.outputs],
            "statuses": [Status(value) for value in self.statuses],
        }

        self._categories = dict(
            self._process_category_config(k, v) for k, v in self.categories.items()
        )

    @staticmethod
    def _process_category_config(key: str, data: dict):
        data = data or {}
        category = Category(key)
        if "include" in data and "exclude" in data:
            raise ValueError("Including and excluding at the same time isn't possible")
        processed_data = {}
        if severities := data.get("severities"):
            processed_data["severities"] = [Severity(v) for v in severities]
        if statuses := data.get("statuses"):
            processed_data["statuses"] = [Status(v) for v in statuses]
        if outputs := data.get("outputs"):
            if category not in CATEGORIES_WITH_OUTPUT:
                raise ValueError(f"{category.value} does not support output filtering.")
            processed_data["outputs"] = [Output(v) for v in outputs]
        if include := data.get("include"):
            if any(filter(lambda v: not v.startswith(f"{category.value}-"), include)):
                raise ValueError(f"Category {category.value} includes incorrect IDs")
            processed_data["include"] = include
        if exclude := data.get("exclude"):
            if any(filter(lambda v: not v.startswith(f"{category.value}-"), exclude)):
                raise ValueError(f"Category {category.value} excludes incorrect IDs")
            processed_data["exclude"] = exclude
        processed_data["acknowledge"] = data.get("acknowledge", False)

        return category, processed_data

    def process(self):
        for company in self.client.companies():
            for category, config in self._categories.items():
                try:
                    self._process_category(
                        company, category, {**self._default_config, **config}
                    )
                except Exception as exc:
                    self.logger.error(
                        "Error when processing a category: %s.", exc, exc_info=True
                    )

    def _process_category(self, company: dict, category: Category, config: dict):
        def _should_send(finding):
            if include := config.get("include"):
                return finding.get("ControlId") in include
            elif exclude := config.get("exclude"):
                return finding.get("ControlId") not in exclude

            return True

        for finding in self.client.get_findings_from_category(
            category,
            company["CompanyId"],
            statuses=config.get("statuses"),
            severities=config.get("severities"),
            outputs=config.get("outputs"),
        ):
            if not _should_send(finding):
                continue
            report = self.new_report()
            report.add("raw", json.dumps({"company": company, "finding": finding}))
            self.send_message(report)
            if config.get("acknowledge"):
                self.client.acknowledge_finding(
                    company.get("CompanyId"), finding.get("FindingId")
                )

    @staticmethod
    def check(parameters: dict) -> list[list[str]] or None:
        errors = []
        definitions = [
            ("severities", Severity),
            ("outputs", Output),
            ("statuses", Status),
        ]
        for key, type_ in definitions:
            try:
                [type_(value) for value in parameters.get(key, [])]
            except ValueError as exc:
                errors.append(["error", f"Error processing '{key}': {exc}."])

        allowed_keys = {
            "severities",
            "outputs",
            "statuses",
            "include",
            "exclude",
            "acknowledge",
        }
        for category, value in parameters.get("categories", {}).items():
            value = value or {}
            try:
                if set(value.keys()) - allowed_keys:
                    raise ValueError("Unsupported config key")
                BlackKiteCollectorBot._process_category_config(category, value)
            except (ValueError, TypeError) as exc:
                errors.append(
                    ["error", f"Error processing category {category}: {exc}."]
                )

        return errors or None


BOT = BlackKiteCollectorBot

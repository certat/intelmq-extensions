# -*- coding: utf-8 -*-
"""
Squelcher Expert marks events as new or old depending on a TTL(ASN, Net, IP).
"""

from __future__ import unicode_literals

from ipaddress import ip_address, ip_network

from intelmq.lib.bot import Bot
from intelmq.lib.message import Event
from intelmq.lib.utils import load_configuration

try:
    import psycopg2
except ImportError:
    psycopg2 = None
try:
    import netaddr
except ImportError:
    netaddr = None

"""
If the event in the DB is older than 2 days, then we also check if it has been sent out.
If this is not the case, we assume the event will be sent out, thus we squelch the new event.
"""
SELECT_QUERY = """
SELECT COUNT(*) FROM {table}
WHERE
"time.source" >= LOCALTIMESTAMP - INTERVAL '%(ttl)s SECONDS' AND
"classification.type" = %(type)s AND
"classification.identifier" = %(identifier)s AND
{source_filters}
notify IS TRUE AND
("time.source" >= LOCALTIMESTAMP - INTERVAL %(sending_interval)s OR
 (sent_at IS NOT NULL AND "time.source" < LOCALTIMESTAMP - INTERVAL %(sending_interval)s)
)
"""

# If the event is newer than sending interval, assume it will be sent soon or already has been,
# regardless of the report id. If the source time is older, ignore events without report id as
# they were most probably forgotten
OPEN_REPORT_QUERY = """
SELECT COUNT(*) FROM {table}
WHERE
"time.source" >= LOCALTIMESTAMP - INTERVAL '%(ttl)s SECONDS' AND
"classification.type" = %(type)s AND
"classification.identifier" = %(identifier)s AND
{source_filters}
notify IS TRUE AND
(
    "time.source" >= LOCALTIMESTAMP - INTERVAL %(sending_interval)s OR
    (rtir_report_id IS NOT NULL AND "time.source" < LOCALTIMESTAMP - INTERVAL %(sending_interval)s)
)
"""

QUERY_MAP = {"base": SELECT_QUERY, "open_report": OPEN_REPORT_QUERY}
JSON_FIELDS = ["extra."]


class SquelcherExpertBot(Bot):
    configuration_path: str = ""
    connect_timeout: int = 5
    database: str = ""
    user: str = ""
    password: str = ""
    host: str = ""
    port: str = ""
    sslmode: str = ""
    autocommit: bool = True
    table: str = "contacts"
    sending_time_interval: int = 1
    overwrite: bool = False
    query: str = "base"  # base, open_report
    source_fields: str = "source.ip"
    filter_ip_only: str = True
    use_ttl_field: str = "extra.ttl"

    _filters_mapping: dict = None

    def init(self):
        self.config = load_configuration(self.configuration_path)

        self.logger.debug("Connecting to PostgreSQL.")
        if psycopg2 is None:
            raise ValueError("Could not import psycopg2. Please install it.")
        if netaddr is None:
            raise ValueError("Could not import netaddr. Please install it.")

        try:
            self.con = psycopg2.connect(
                database=self.database,
                user=self.user,
                password=self.password,
                host=self.host,
                port=self.port,
                sslmode=self.sslmode,
                connect_timeout=self.connect_timeout,
            )
            self.cur = self.con.cursor()
            self.con.autocommit = self.autocommit

        except Exception:
            self.logger.exception("Failed to connect to database.")
            self.stop()
        self.logger.info("Connected to PostgreSQL.")

        self.query_tpl = self._build_query()
        self.convert_config()

    def _build_query(self):
        # TODO: Build it using sql-safe syntax
        # TODO: ensure source field is in the harmonization
        template = QUERY_MAP[self.query]
        self._filters_mapping = dict()
        for idx, field in enumerate(self.source_fields.split(",")):
            self._filters_mapping[field] = f"source_{idx}"

        conditions = []
        for field, filter_key in self._filters_mapping.items():
            json_fields = [f for f in JSON_FIELDS if field.startswith(f)]
            if json_fields:
                conditions.append(
                    (
                        f'"{json_fields[0][:-1]}" ->> \'{field.replace(json_fields[0], "")}\''
                        f" IS NOT DISTINCT FROM %({filter_key})s AND"
                    )
                )
            else:
                # IS NOT DISTINCT makes a good job, but doesn't play well with
                # unique indexes unless probably PostgreSQL 15 and UNIQUE NULLS NOT DISTINCT
                # index configuration
                conditions.append(
                    f"""CASE WHEN %({filter_key})s IS null THEN
                            "{field}" is null
                            ELSE "{field}" = %({filter_key})s
                        END AND
                    """
                )
        return template.format(table=self.table, source_filters="\n".join(conditions))

    def convert_config(self):
        for rule_index, ruleset in enumerate(self.config):
            for key, value in ruleset[0].items():
                if isinstance(value, list):
                    self.config[rule_index][0][key] = tuple(value)
                if isinstance(value, dict):
                    self.config[rule_index][0][key] = tuple(value.items())

    def convert_event(self, event):
        event_copy = event.to_dict()
        for key, value in event_copy.items():
            if isinstance(value, list):
                event_copy[key] = tuple(value)
            if isinstance(value, dict):
                event_copy[key] = tuple(value.items())
        return event_copy

    def process(self):
        event = self.receive_message()

        if "notify" in event and not self.overwrite:
            self.logger.debug(
                "Notify field present and not allowed to overwrite, skipping."
            )
            self.modify_end(event)
            return

        if self.filter_ip_only:
            if "source.ip" not in event and "source.fqdn" in event:
                self.logger.debug(
                    "Filtering restricted to IPs, setting notify=true for domain event."
                )
                event.add("notify", True, overwrite=True)
                self.modify_end(event)
                return
            if "source.asn" not in event:
                self.logger.debug("Discarding event as it lacks AS number.")
                event.add("notify", False, overwrite=True)
                self.modify_end(event)
                return
        ttl = None

        if self.use_ttl_field:
            try:
                ttl = int(event[self.use_ttl_field])
            except KeyError:
                pass

        if ttl is None:
            for ruleset in self.config:
                condition = ruleset[0].copy()
                conditions = []
                if "source.network" in condition and "source.ip" in event:
                    conditions.append(
                        ip_address(event["source.ip"])
                        in ip_network(condition["source.network"])
                    )
                    del condition["source.network"]
                if "source.iprange" in condition and "source.ip" in event:
                    conditions.append(
                        event["source.ip"]
                        in netaddr.IPRange(*condition["source.iprange"])
                    )
                    del condition["source.iprange"]
                if set(condition.items()).issubset(
                    self.convert_event(event).items()
                ) and all(conditions):
                    ttl = ruleset[1]["ttl"]
                    break

        self.logger.debug(
            "Found TTL {} for ({}, {})." "".format(
                ttl, event.get("source.asn"), event.get("source.ip")
            )
        )

        try:
            if ttl >= 0:
                source_filters = {
                    filter_key: event.get(field)
                    for field, filter_key in self._filters_mapping.items()
                }
                self.cur.execute(
                    self.query_tpl,
                    {
                        "ttl": ttl,
                        "type": event["classification.type"],
                        "identifier": event["classification.identifier"],
                        "sending_interval": self.sending_time_interval,
                        **source_filters,
                    },
                )
                result = self.cur.fetchone()[0]
            else:  # never notify with ttl -1
                result = 1
        except (
            psycopg2.InterfaceError,
            psycopg2.InternalError,
            psycopg2.OperationalError,
            AttributeError,
        ):
            self.logger.exception("Cursor has been closed, connecting again.")
            self.init()
        else:
            if result == 0:
                notify = True
            else:
                notify = False

            event.add("notify", notify, overwrite=True)
            self.modify_end(event)

    def shutdown(self):
        try:
            self.cur.close()
        except Exception:
            pass
        try:
            self.con.close()
        except Exception:
            pass

    def modify_end(self, event):
        self.send_message(event)
        self.acknowledge_message()

    @staticmethod
    def check(parameters):
        retval = []
        try:
            config = load_configuration(parameters["configuration_path"])
        except ValueError as exc:
            return [["error", "Could not load configuration: %r." % exc]]
        for ruleset in config:
            condition = ruleset[0].copy()
            if "source.network" in condition:
                try:
                    ip_network(condition["source.network"])
                except ValueError as exc:
                    retval += [
                        [
                            "warning",
                            "%r is not a valid IP network: %r."
                            % (condition["source.network"], exc),
                        ]
                    ]
                del condition["source.network"]
            if "source.iprange" in condition:
                try:
                    netaddr.IPRange(*condition["source.iprange"])
                except ValueError as exc:
                    retval += [
                        [
                            "warning",
                            "%r is not a valid IP range: %r."
                            % (condition["source.iprange"], exc),
                        ]
                    ]
                del condition["source.iprange"]
            try:
                Event(condition)
            except Exception as exc:
                retval += [
                    ["warning", "Failed to parse conditions as Event: %r." % (exc)]
                ]
            try:
                int(ruleset[1]["ttl"])
            except ValueError as exc:
                retval += [
                    ["error", "%r is not a valid TTL: %r." % (ruleset[1]["ttl"], exc)]
                ]
        return retval if retval else None


BOT = SquelcherExpertBot

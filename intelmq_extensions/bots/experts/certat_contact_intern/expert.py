# -*- coding: utf-8 -*-
"""
CERT.at geolocate the national CERT abuse service
"""
from intelmq.lib.bot import Bot

try:
    import psycopg2
except ImportError:
    psycopg2 = None


class CERTatContactExpertBot(Bot):
    connect_timeout = 5
    database: str = ""
    user: str = ""
    password: str = ""
    host: str = ""
    port: str = ""
    sslmode: str = ""
    autocommit: bool = True
    table: str = "contacts"
    column: str = ""
    feed_code: str = ""
    ascolumn: str = ""
    overwrite: bool = False

    def init(self):
        self.logger.debug("Connecting to database.")
        if psycopg2 is None:
            self.logger.error("Could not import psycopg2. Please install it.")
            self.stop()

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

        self.query = (
            'SELECT "{column}", "can-see-tlp-amber_{feed_code}"'
            ' FROM "{table}" WHERE "{ascolumn}" = %s'
            "".format(
                table=self.table,
                column=self.column,
                feed_code=self.feed_code,
                ascolumn=self.ascolumn,
            )
        )

    def process(self):
        event = self.receive_message()
        default_destination_visible = (
            True if event.get("feed.code") != self.feed_code else False
        )

        if "source.asn" not in event:
            self.logger.info("source.asn not present in event. Skipping event.")
            event.add(
                "destination_visible",
                default_destination_visible,
                overwrite=self.overwrite,
            )
            self.send_message(event)
            self.acknowledge_message()
            return

        if "source.abuse_contact" in event and not self.overwrite:
            event.add(
                "destination_visible",
                default_destination_visible,
                overwrite=self.overwrite,
            )
            self.send_message(event)
            self.acknowledge_message()
            return

        try:
            self.logger.debug(
                "Executing %r." % self.cur.mogrify(self.query, (event["source.asn"],))
            )
            self.cur.execute(self.query, (event["source.asn"],))
        except (
            psycopg2.InterfaceError,
            psycopg2.InternalError,
            psycopg2.OperationalError,
            AttributeError,
        ):
            self.logger.exception("Database connection problem, connecting again.")
            self.init()
        else:
            if self.cur.rowcount > 1:
                raise ValueError(
                    "Lookup returned more than one result. Please inspect."
                )
            elif self.cur.rowcount == 1:
                result = self.cur.fetchone()
                self.logger.debug(
                    "Changing `source.abuse_contact` from %r to %r."
                    % (event.get("source.abuse_contact"), result[0])
                )

                event.add("source.abuse_contact", result[0], overwrite=self.overwrite)

                if event["feed.code"] == self.feed_code:
                    if result[1]:
                        event.add("destination_visible", True, overwrite=self.overwrite)
                    else:
                        event.add(
                            "destination_visible", False, overwrite=self.overwrite
                        )
                else:
                    event.add("destination_visible", True, overwrite=self.overwrite)

            else:
                self.logger.debug("No contact found.")
                event.add(
                    "destination_visible",
                    default_destination_visible,
                    overwrite=self.overwrite,
                )

            self.send_message(event)
            self.acknowledge_message()


BOT = CERTatContactExpertBot

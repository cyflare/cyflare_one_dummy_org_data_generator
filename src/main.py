#!/usr/bin/env python

import argparse
import os
from argparse import Namespace
from datetime import datetime

import pytz
from dateutil.rrule import DAILY, rrule

from db import PostgreSQLClient
from models import AlertStat, Ticket
from settings import PROJECT_NAME, logger


class Generator:
    def __init__(self, args: Namespace) -> None:
        self._args = args
        self._start_date = pytz.utc.localize(
            datetime.strptime(
                f"{self._args.start_date}-{now_time}",
                DATETIME_FORMAT,
            )
        )
        self._end_date = pytz.utc.localize(
            datetime.strptime(
                f"{self._args.end_date}-{now_time}",
                DATETIME_FORMAT,
            )
        )

        self._db_client = PostgreSQLClient(
            os.environ["POSTGRESQL_HOST"],
            os.environ["POSTGRESQL_USER"],
            os.environ["POSTGRESQL_PASSWORD"],
            os.environ["POSTGRESQL_DATABASE"],
            os.environ["POSTGRESQL_PORT"],
        )

    def execute(self) -> None:
        """Executes the appropriate action based on the input args."""
        number_of_elements = self._args.number_of_elements_per_date
        if self._args.create_tickets or self._args.create_all:
            for i in rrule(DAILY, dtstart=self._start_date, until=self._end_date):
                tickets = self._generate_objects(
                    Ticket,
                    number_of_elements=number_of_elements,
                    extra={"db_client": self._db_client, "datetime_for_create": i},
                )
                self._save_to_database("analytics_api_v1_ticket", tickets)

        if self._args.create_alertstats or self._args.create_all:
            for i in rrule(DAILY, dtstart=self._start_date, until=self._end_date):
                alert_stats = self._generate_objects(
                    AlertStat,
                    number_of_elements=number_of_elements,
                    extra={"datetime_for_create": i},
                )
                self._save_to_database("analytics_api_v1_alertstat", alert_stats)

    def _generate_objects(self, model, number_of_elements, extra=None):
        if not extra:
            extra = {}
        logger.info(
            "Generating {} elements for {} on {}".format(
                number_of_elements, model.__name__, extra.get("datetime_for_create")
            )
        )
        data = []
        for i in range(number_of_elements):
            data.append(model(**extra))
        return data

    def _save_to_database(self, table_name, records):
        for record in records:
            self._db_client.insert_record_into_database(table_name, record)

        logger.info(
            "Successfully completed saving data to One API DB ({})".format(table_name)
        )


if __name__ == "__main__":
    DATE_FORMAT = "%Y%m%d"
    TIME_FORMAT = "%H%M"
    DATETIME_FORMAT = f"{DATE_FORMAT}-{TIME_FORMAT}"

    now = pytz.utc.localize(datetime.utcnow())
    now_time = now.time().strftime(TIME_FORMAT)

    parser = argparse.ArgumentParser(
        description="A terminal client to interact with the demo data generator."
    )
    subparsers = parser.add_subparsers(title="Sub Commands", dest="subcommand")

    parser_generate = subparsers.add_parser(
        "generate",
        help="Create elements for provided date range (or today's date if not provided) and save them into database.",
    )

    parser_generate.add_argument(
        "--create_tickets",
        type=bool,
        default=False,
        help="Boolean that defines if tickets need to be created.",
    )
    parser_generate.add_argument(
        "--create_alertstats",
        type=bool,
        default=False,
        help="Boolean that defines if alertstats need to be created.",
    )
    parser_generate.add_argument(
        "--create_all",
        type=bool,
        default=False,
        help="Boolean that defines if elements of all models need to be created.",
    )
    parser_generate.add_argument(
        "--start_date",
        default=now.strftime(DATE_FORMAT),
        help="Start date for the data generation.",
    )
    parser_generate.add_argument(
        "--end_date",
        default=now.strftime(DATE_FORMAT),
        help="End date for the data generation.",
    )
    parser_generate.add_argument(
        "--number_of_elements_per_date",
        required=True,
        type=int,
        help="Number of elements that need to be created for each model per day.",
    )

    args = parser.parse_args()

    if "generate" == args.subcommand:

        logger.info("Running {}.".format(PROJECT_NAME))

        runner = Generator(args)
        runner.execute()

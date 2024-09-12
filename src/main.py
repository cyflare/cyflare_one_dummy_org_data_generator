#!/usr/bin/env python

import argparse
import os
from argparse import Namespace

from db import PostgreSQLClient
from models import Ticket, AlertStat
from settings import PROJECT_NAME, logger


class Runner:
    def __init__(self, args: Namespace) -> None:
        self._args = args
        self._db_client = PostgreSQLClient(
            os.environ["POSTGRESQL_HOST"],
            os.environ["POSTGRESQL_USER"],
            os.environ["POSTGRESQL_PASSWORD"],
            os.environ["POSTGRESQL_DATABASE"],
            os.environ["POSTGRESQL_PORT"],
        )

    def execute(self) -> None:
        """Executes the appropriate action based on the input args."""
        number_of_elements = self._args.number_of_elements
        if self._args.create_tickets or self._args.create_all:
            tickets = self._generate_objects(
                Ticket,
                number_of_elements=number_of_elements,
                extra={"db_client": self._db_client},
            )
            self._save_to_database("analytics_api_v1_ticket", tickets)

        if self._args.create_alertstats or self._args.create_all:
            alert_stats = self._generate_objects(
                AlertStat, number_of_elements=number_of_elements
            )
            self._save_to_database("analytics_api_v1_alertstat", alert_stats)

    def _generate_objects(self, model, number_of_elements, extra=None):
        if not extra:
            extra = {}
        logger.info(
            "Generating {} elements for {}".format(number_of_elements, model.__name__)
        )
        data = []
        for i in range(number_of_elements):
            data.append(model(**extra))

        logger.info("Successfully completed the data generation")
        return data

    def _save_to_database(self, table_name, records):
        logger.info("Saving records to One API DB ({})".format(table_name))

        for record in records:
            self._db_client.insert_record_into_database(table_name, record)

        logger.info("Successfully completed saving data to One API DB")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="A terminal client to interact with the demo data generator."
    )
    subparsers = parser.add_subparsers(title="Sub Commands", dest="subcommand")

    parser_run = subparsers.add_parser(
        "run",
        help="Create elements and save them into database.",
    )

    parser_run.add_argument(
        "--create_tickets",
        type=bool,
        default=False,
        help="Boolean that defines if tickets need to be created.",
    )
    parser_run.add_argument(
        "--create_alertstats",
        type=bool,
        default=False,
        help="Boolean that defines if alertstats need to be created.",
    )
    parser_run.add_argument(
        "--create_all",
        type=bool,
        default=False,
        help="Boolean that defines if elements of all models need to be created.",
    )
    parser_run.add_argument(
        "--number_of_elements",
        type=int,
        help="Number of elements that need to be created for each model.",
    )

    args = parser.parse_args()

    if "run" == args.subcommand:
        logger.info("Running {}".format(PROJECT_NAME))

        runner = Runner(args)
        runner.execute()

import dataclasses

import psycopg2
import psycopg2.extras


class PostgreSQLClient:
    def __init__(
        self,
        host,
        user,
        password,
        database,
        port,
        cursor_class=psycopg2.extras.RealDictCursor,
        auto_commit=True,
    ):
        self._host = host
        self._user = user
        self._password = password
        self._database = database
        self._port = port
        self._cursor_class = cursor_class
        self._auto_commit = auto_commit

        self._connection = psycopg2.connect(
            database=self._database,
            host=self._host,
            user=self._user,
            password=self._password,
            port=self._port,
            cursor_factory=self._cursor_class,
        )
        self._connection.autocommit = self._auto_commit

    def get_latest_ticket_id(self):
        column_name = "max_id"
        sql = "SELECT MAX(id) as %s from analytics_api_v1_ticket" % column_name
        with self._connection.cursor() as cursor:
            cursor.execute(sql)
            result = cursor.fetchone()
            if column_name not in result or not result[column_name]:
                return 0
        return int(result[column_name])

    def insert_record_into_database(self, table_name, record):
        with self._connection.cursor() as cursor:
            record_fields = [b.name for b in dataclasses.fields(record)]
            record_dict = dataclasses.asdict(record)
            sql = (
                f"INSERT INTO {table_name} ({', '.join(record_fields)}) "
                f"VALUES ({', '.join(['%s'] * len(record_fields))})"
            )
            cursor.execute(
                sql,
                [record_dict[field] for field in record_fields],
            )

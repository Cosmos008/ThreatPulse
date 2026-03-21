from datetime import date, datetime
import time

import pg8000

from shared.config import (
    get_postgres_config,
    get_postgres_retry_delay_seconds,
    get_postgres_retry_attempts,
)


def connect_with_retry():
    config = get_postgres_config()
    last_error = None

    for _ in range(get_postgres_retry_attempts()):
        try:
            return pg8000.dbapi.connect(
                host=config["host"],
                port=int(config.get("port", "5432")),
                database=config["database"],
                user=config["user"],
                password=config["password"]
            )
        except Exception as exc:
            last_error = exc
            time.sleep(get_postgres_retry_delay_seconds())

    raise last_error


def rows_to_dicts(cursor, rows):
    columns = [column[0] for column in cursor.description]
    normalized_rows = []

    for row in rows:
        entry = {}

        for column, value in zip(columns, row):
            if isinstance(value, (datetime, date)):
                entry[column] = value.isoformat()
            else:
                entry[column] = value

        normalized_rows.append(entry)

    return normalized_rows

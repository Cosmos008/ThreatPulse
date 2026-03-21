from shared.database_utils import connect_with_retry


def get_connection():
    return connect_with_retry()

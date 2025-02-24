from datetime import datetime
import pytz
import logging

class MessageDateFunctions():
    @staticmethod
    def parse_timestamp_iso8601_to_datetime(timestamp_str: str) -> datetime:
        """
        Parse an ISO 8601 timestamp string into a timezone-aware datetime object.

        Args:
            timestamp_str (str): The timestamp string to parse.

        Returns:
            datetime: A timezone-aware datetime object.
        """
        try:
            dt = datetime.fromisoformat(timestamp_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=pytz.UTC)  # Default to UTC if timezone is missing
            return dt.astimezone(pytz.UTC)  # Convert to UTC for consistency
        except ValueError as e:
            raise e
        
    def convert_iso8601_to_datetime_string(self, datetime_str_iso8601: str) -> str:
        """
        Convert ISO 8601 datetime string to MySQL-compatible format.

        Args:
            datetime_str_iso8601 (str): The datetime string in ISO 8601 format.

        Returns:
            str: The datetime string in 'YYYY-MM-DD HH:MM:SS' format.
        """
        try:
            dt = datetime.fromisoformat(datetime_str_iso8601.replace("Z", "+00:00"))
            return dt.strftime('%Y-%m-%d %H:%M:%S')
        except ValueError:
            logging.error(f"Invalid datetime format: {datetime_str_iso8601}")
            raise

    def convert_datetime_to_iso8601_string(self, dt: datetime) -> str:
        """
        Convert a Python datetime object to an ISO 8601 formatted string.

        Args:
            dt (datetime): The datetime object to convert.

        Returns:
            str: The datetime string in ISO 8601 format.
        """
        try:
            # Set timezone to UTC
            dt = dt.replace(tzinfo=pytz.UTC)
            # Return the ISO 8601 formatted string
            return dt.isoformat()
        except ValueError:
            logging.error(f"Invalid datetime format: {dt}")
            raise

    def convert_datetime_string_to_iso8601_string(self, datetime_str: str) -> str:
        """
        Convert a MySQL-compatible datetime string to ISO 8601 format.

        Args:
            datetime_str (str): The datetime string in 'YYYY-MM-DD HH:MM:SS' format.

        Returns:
            str: The datetime string in ISO 8601 format.
        """
        try:
            # Parse the MySQL datetime string
            dt = datetime.strptime(datetime_str, '%Y-%m-%d %H:%M:%S')
            # Set timezone to UTC
            dt = dt.replace(tzinfo=pytz.UTC)
            # Return the ISO 8601 formatted string
            return dt.isoformat()
        except ValueError:
            logging.error(f"Invalid datetime format: {datetime_str}")
            raise

    def convert_mysql_datetime_string_to_datetime(self, datetime_str: str) -> datetime:
        """
        Convert a MySQL-compatible datetime string to a Python datetime object.

        Args:
            datetime_str (str): The datetime string in 'YYYY-MM-DD HH:MM:SS' format.

        Returns:
            datetime: A timezone-aware Python datetime object (UTC).
        """
        try:
            # Parse the MySQL datetime string
            dt = datetime.strptime(datetime_str, '%Y-%m-%d %H:%M:%S')
            # Set timezone to UTC
            dt = dt.replace(tzinfo=pytz.UTC)
            return dt
        except ValueError:
            logging.error(f"Invalid datetime format: {datetime_str}")
            raise
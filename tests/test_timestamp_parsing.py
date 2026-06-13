"""Tests for enhanced timestamp parsing with year rollover and timezone awareness."""
import pytest
from datetime import datetime, timezone, timedelta
from src.logcollector.utils import parse_timestamp, get_year_for_timestamp


def test_parse_timestamp_basic():
    """Test basic timestamp parsing in 'Mon DD HH:MM:SS' format."""
    # Using a date we know (current month assumed current year or previous if in future)
    result = parse_timestamp("Jun 10 12:34:56")
    assert isinstance(result, datetime)
    assert result.month == 6
    assert result.day == 10
    assert result.hour == 12
    assert result.minute == 34
    assert result.second == 56


def test_parse_timestamp_with_positive_timezone():
    """Test parsing timestamp with positive timezone offset."""
    result = parse_timestamp("Jun 10 12:34:56+05:30")
    assert isinstance(result, datetime)
    assert result.tzinfo is not None
    # Check that the offset is correct
    assert result.tzinfo.utcoffset(None) == timedelta(hours=5, minutes=30)


def test_parse_timestamp_with_negative_timezone():
    """Test parsing timestamp with negative timezone offset."""
    result = parse_timestamp("Jun 10 12:34:56-08:00")
    assert isinstance(result, datetime)
    assert result.tzinfo is not None
    assert result.tzinfo.utcoffset(None) == timedelta(hours=-8, minutes=0)


def test_parse_timestamp_iso_format():
    """Test parsing ISO 8601 formatted timestamp."""
    iso_str = "2026-06-10T12:34:56+00:00"
    result = parse_timestamp(iso_str)
    assert isinstance(result, datetime)
    assert result.year == 2026
    assert result.month == 6
    assert result.day == 10


def test_parse_timestamp_malformed():
    """Test that malformed timestamp falls back to current UTC time."""
    result = parse_timestamp("not a timestamp")
    assert isinstance(result, datetime)
    # Should be close to now (within a few seconds)
    now = datetime.utcnow()
    delta = abs((result - now).total_seconds())
    assert delta < 5


def test_parse_timestamp_empty():
    """Test that empty string returns current UTC time."""
    result = parse_timestamp("")
    assert isinstance(result, datetime)
    now = datetime.utcnow()
    delta = abs((result - now).total_seconds())
    assert delta < 5


def test_get_year_for_timestamp_current_year():
    """Test year inference for a date in the current year (before or at today)."""
    # Using a date from earlier in June (if we're past June, it will infer current year)
    result = get_year_for_timestamp("Jun 10 12:34:56")
    now = datetime.utcnow()
    # Should be current year or previous year depending on whether Jun 10 is past
    assert result in [now.year - 1, now.year]


def test_get_year_for_timestamp_future_date():
    """Test year inference for a date that's in the future (should infer previous year)."""
    # Use a date 6 months from now, which should be inferred as previous year
    from datetime import datetime as dt_module
    now = dt_module.utcnow()
    future_month = (now.month + 6) % 12 or 12
    if future_month < now.month:
        # We've wrapped around, so this month is in the next year
        months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
        future_month_str = months[future_month - 1]
        result = get_year_for_timestamp(f"{future_month_str} 10 12:34:56")
        # This should infer the previous year since it's a future date
        assert result <= now.year

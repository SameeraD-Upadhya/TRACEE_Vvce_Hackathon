from .auth_log import AuthLogParser
from .json_event import JsonEventParser
from .systemd_journal import SystemdJournalParser
from .windows_event import WindowsEventParser


PARSERS = [
    AuthLogParser(),
    JsonEventParser(),
    SystemdJournalParser(),
    WindowsEventParser(),
]


def get_parsers():
    return PARSERS

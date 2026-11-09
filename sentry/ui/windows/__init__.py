"""Tool desktop windows exports."""

from sentry.ui.windows.netsentry_window import NetSentryWindow
from sentry.ui.windows.logsentinel_window import LogSentinelWindow
from sentry.ui.windows.certsentry_window import CertSentryWindow
from sentry.ui.windows.subnetsweep_window import SubnetSweepWindow
from sentry.ui.windows.integrityguard_window import IntegrityGuardWindow
from sentry.ui.windows.dnsprobe_window import DnsProbeWindow
from sentry.ui.windows.trafficsentry_window import TrafficSentryWindow

TOOL_WINDOW_MAP = {
    "netsentry": NetSentryWindow,
    "logsentinel": LogSentinelWindow,
    "certsentry": CertSentryWindow,
    "subnetsweep": SubnetSweepWindow,
    "integrityguard": IntegrityGuardWindow,
    "dnsprobe": DnsProbeWindow,
    "trafficsentry": TrafficSentryWindow,
}

__all__ = [
    "NetSentryWindow",
    "LogSentinelWindow",
    "CertSentryWindow",
    "SubnetSweepWindow",
    "IntegrityGuardWindow",
    "DnsProbeWindow",
    "TrafficSentryWindow",
    "TOOL_WINDOW_MAP",
]


import os
import re
from termcolor import colored


# Adapted from https://github.com/p0dalirius/LDAPmonitor/blob/6f9dfcbaacd30d68d1f040c705c3b536722faa80/python/pyLDAPmonitor.py#L46
class Logger:
    def __init__(self, debug=False, logfile=None, nocolors=False):
        super().__init__()
        self.__debug = debug
        self.__nocolors = nocolors
        self.logfile = logfile

        if self.logfile is not None:
            if os.path.exists(self.logfile):
                k = 1
                while os.path.exists(self.logfile + (f".{k}")):
                    k += 1
                self.logfile = self.logfile + (f".{k}")
            open(self.logfile, "w").close()

    def print(self, message=""):
        nocolor_message = re.sub(r"\x1b[\[]([0-9;]+)m", "", message)
        if self.__nocolors:
            print(nocolor_message)
        else:
            print(message)
        if self.logfile is not None:
            with open(self.logfile, "a") as f:
                f.write(nocolor_message + "\n")

    def info(self, message):
        nocolor_message = re.sub(r"\x1b[\[]([0-9;]+)m", "", message)
        if self.__nocolors:
            print(f"[*] {nocolor_message}")
        else:
            print(colored(f"[*] {message}", "blue", attrs=["bold"]))
        if self.logfile is not None:
            with open(self.logfile, "a") as f:
                f.write(nocolor_message + "\n")

    def success(self, message):
        nocolor_message = re.sub(r"\x1b[\[]([0-9;]+)m", "", message)
        if self.__nocolors:
            print(f"[+] {nocolor_message}")
        else:
            print(colored(f"[+] {message}", "green", attrs=["bold"]))
        if self.logfile is not None:
            with open(self.logfile, "a") as f:
                f.write(nocolor_message + "\n")

    def debug(self, message):
        if self.__debug:
            nocolor_message = re.sub(r"\x1b[\[]([0-9;]+)m", "", message)
            if self.__nocolors:
                print(f"[debug] {nocolor_message}")
            else:
                print(f"[debug] {message}")
            if self.logfile is not None:
                with open(self.logfile, "a") as f:
                    f.write(f"[debug] {nocolor_message}\n")

    def error(self, message):
        nocolor_message = re.sub(r"\x1b[\[]([0-9;]+)m", "", message)
        if self.__nocolors:
            print(f"[!] {nocolor_message}")
        else:
            print(colored(f"[!] {message}", "red", attrs=["bold"]))
        if self.logfile is not None:
            with open(self.logfile, "a") as f:
                f.write(f"[!] {nocolor_message}\n")


# Event Log Stuff
EVENT_LEVEL = {
    0: "LogAlways",
    1: "Critical",
    2: "Error",
    3: "Warning",
    4: "Informational",
    5: "Verbose",
}

KEYWORDS = {
    -1: "All",
    0x0: "None",
    0x2_0000_0000_0000: "MicrosoftTelemetry/WdiContext",
    0x4_0000_0000_0000: "WdiDiagnostic",
    0x8_0000_0000_0000: "Sqm",
    0x10_0000_0000_0000: "AuditFailure/CorrelationHint",
    0x20_0000_0000_0000: "AuditSuccess",
    0x40_0000_0000_0000: "EventLogClassic",
}

TASKS = {
    0x3100: "Logon",
    0x3101: "Logoff",
    0x3104: "Special Logon",
    0x3800: "Credential Validation",
    0x3801: "Kerberos Service Ticket Operations",
}

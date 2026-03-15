import argparse
import time
from impacket.dcerpc.v5 import transport, even6
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, DCERPCException
from impacket.dcerpc.v5.epm import hept_map
from EVENmonitor.utils import Logger, EVENT_LEVEL, KEYWORDS, TASKS
from EVENmonitor.even6_parser import ResultSet
from termcolor import colored
import xml.etree.ElementTree as ET
import xml.dom.minidom as minidom


class MSEven6Trigger:
    def __init__(self, logger: Logger, args):
        self.logger = logger
        self.args = args
        self.dce = None

    def connect(self, username, password, domain, lmhash, nthash, aesKey, target, doKerberos, dcHost, pipe):
        rpctransport = transport.DCERPCTransportFactory(hept_map(target, even6.MSRPC_UUID_EVEN6, protocol="ncacn_ip_tcp"))
        if hasattr(rpctransport, "set_credentials"):
            rpctransport.set_credentials(
                username=username,
                password=password,
                domain=domain,
                lmhash=lmhash,
                nthash=nthash,
                aesKey=aesKey,
            )
        if doKerberos:
            rpctransport.set_kerberos(doKerberos, kdcHost=dcHost)
        rpctransport.setRemoteHost(target)
        self.dce = rpctransport.get_dce_rpc()
        if doKerberos:
            self.dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
        self.dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        self.logger.info(f"Connecting to {target}...")
        try:
            self.dce.connect()
        except Exception as e:
            self.logger.error(f"Something went wrong, check error status => {e!s}")
            return
        try:
            self.dce.bind(even6.MSRPC_UUID_EVEN6)
            self.logger.success("Successfully bound to MS-EVEN6!")
        except Exception as e:
            self.logger.error(f"Something went wrong, check error status => {e!s}")
            return

    def query(self, numRequestedRecords=100, timeOut=1000):
        req = even6.EvtRpcRemoteSubscriptionNext()
        req["Handle"] = self.subscription_handle
        req["NumRequestedRecords"] = numRequestedRecords
        req["TimeOut"] = timeOut
        req["Flags"] = 0
        return self.dce.request(req)

    def watch(self, channel="Security", event_id=None, grep=None):
        res = even6.hEvtRpcRegisterRemoteSubscription(
            self.dce,
            channelPath=channel,
            query="*",
            bookmarkXml="",
            flags=even6.EvtSubscribePull | even6.EvtSubscribeToFutureEvents
        )
        self.subscription_handle = res["Handle"]

        self.logger.info("Watching for events...")
        try:
            while True:
                res = self.query()
                if res["NumActualRecords"] != 0:
                    self.logger.success(f"New event received: {res['NumActualRecords']} records")
                    xmlString = MSEven6Result(res)._xml
                    for event in xmlString:
                        tree = ET.ElementTree(ET.fromstring(event))
                        xml_str = minidom.parseString(ET.tostring(tree.getroot())).toprettyxml(indent="  ")
                        cleaned = "\n".join([line for line in xml_str.split("\n") if line.strip()]) + "\n"
                        self.logger.debug(cleaned)

                        # Parse the Event XML
                        # Parse header information
                        ns = {"ns0": "http://schemas.microsoft.com/win/2004/08/events/event"}
                        creation_time = tree.find(".//ns0:TimeCreated", namespaces=ns).get("SystemTime")
                        channel_str = tree.find(".//ns0:Channel", namespaces=ns).text
                        event_id_str = tree.find(".//ns0:EventID", namespaces=ns).text
                        level_str = EVENT_LEVEL[int(tree.find(".//ns0:Level", namespaces=ns).text)]
                        # Get Keyword and flip first bit because Microsoft
                        keywords_int = int(tree.find(".//ns0:Keywords", namespaces=ns).text, 16) ^ 0b1000000000000000000000000000000000000000000000000000000000000000
                        keywords_str = KEYWORDS.get(keywords_int, f"Unknown ({hex(keywords_int)})")
                        # Get the task number for the task category
                        task_number = int(tree.find(".//ns0:Task", namespaces=ns).text)
                        task_str = TASKS.get(task_number, f"Unknown Task ({task_number})")

                        # Filter by event ID if specified
                        if event_id and not self.args.verbose:
                            event_ids = [eid.strip() for eid in event_id.split(",")]
                            if event_id_str not in event_ids:
                                continue

                        # Filter by grep if specified
                        if grep and grep not in cleaned and not self.args.verbose:
                            continue

                        # Print the event header information and continue if verbose
                        self.logger.print(f"[{colored(creation_time, 'blue')}] Channel: {colored(channel_str, 'green', attrs=['bold'])}, Event ID: {colored(event_id_str, 'green', attrs=['bold'])}, Level: {colored(level_str, 'green', attrs=['bold'])}, Keywords: {colored(keywords_str, 'green', attrs=['bold'])}, Task: {colored(task_str, 'green', attrs=['bold'])}")
                        if self.args.verbose:
                            continue

                        # Extract EventData
                        event_data = tree.find(".//ns0:EventData", namespaces=ns)
                        data = {elem.get("Name"): elem.text for elem in event_data.findall(".//ns0:Data", namespaces=ns)}
                        for child in event_data:
                            if child.tag.endswith("Binary"):
                                data["Binary"] = child.text
                        for key, value in data.items():
                            if key != list(data.keys())[-1]:
                                self.logger.print(f"├─{colored('' + key, 'cyan'):<40}: {value}")
                            else:
                                self.logger.print(f"└─{colored('' + key, 'cyan'):<40}: {value}")
                time.sleep(0.1)

        except KeyboardInterrupt:
            self.logger.print()
            self.logger.error("Exiting due to keyboard interrupt.")


class MSEven6Result:
    def __init__(self, buffer: bytes):
        self._xml = []
        self._index = 0

        for idx in range(buffer["NumActualRecords"]):
            offset = buffer["EventDataIndices"][idx]["Data"]
            size = buffer["EventDataSizes"][idx]["Data"]
            self._xml.append(ResultSet(b"".join(buffer["ResultBuffer"][offset:offset + size])).xml())

    def __iter__(self):
        self._resp = None
        return self

    def __next__(self):
        if self._index >= len(self._xml):
            raise StopIteration
        self._resp = self._xml[self._index]
        self._index += 1
        return self._resp


def main():
    # Mostly stolen from LDAPmonitor
    parser = argparse.ArgumentParser(description="EVENmonitor - Monitor and Analyze the Windows Event Log")
    parser.add_argument("--dc-ip", required=True, dest="dc_ip", metavar="ip address", help="IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted it will use the domain part (FQDN) specified in the identity parameter")
    parser.add_argument("-u", "--user", required=True, dest="auth_username", metavar="USER", action="store", help="user to authenticate with")
    parser.add_argument("-d", "--domain", required=True, dest="auth_domain", metavar="DOMAIN", action="store", help="(FQDN) domain to authenticate to")
    parser.add_argument("--kdcHost", dest="kdcHost", metavar="FQDN KDC", help="FQDN of KDC for Kerberos.")
    parser.add_argument("-k", "--kerberos", dest="use_kerberos", action="store_true", help="Use Kerberos authentication. Grabs credentials from .ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line")

    cred = parser.add_mutually_exclusive_group()
    cred.add_argument("-p", "--password", dest="auth_password", metavar="PASSWORD", action="store", help="password to authenticate with")
    cred.add_argument("-H", "--hashes", dest="auth_hashes", action="store", metavar="[LMHASH:]NTHASH", help="NT/LM hashes, format is LMhash:NThash")
    cred.add_argument("--aes-key", dest="aesKey", action="store", metavar="hex key", help="AES key to use for Kerberos Authentication (128 or 256 bits)")

    misc = parser.add_argument_group("Logging")
    misc.add_argument("--verbose", dest="verbose", action="store_true", default=False, help="Verbose mode. Only shows event header information.")
    misc.add_argument("--debug", dest="debug", action="store_true", default=False, help="Debug mode.")
    misc.add_argument("--no-colors", dest="no_colors", action="store_true", default=False, help="No colors mode.")
    misc.add_argument("-l", "--logfile", dest="logfile", type=str, default=None, help="Log file to save output to.")

    filtering = parser.add_argument_group("Filtering")
    filtering.add_argument("--channel", dest="channel", default="Security", metavar="CHANNEL", help="Event log channel to monitor (default: Security).")
    filtering.add_argument("--event-id", dest="event_id", default=None, metavar="EVENT_ID", help="Filter by specific event ID. Multiple IDs can be specified as a comma-separated list (e.g., 4624, 4625).")
    filtering.add_argument("--grep", dest="grep", default=None, metavar="GREP", help="Filter events by a specific string. Only events containing this string will be displayed.")

    args = parser.parse_args()

    logger = Logger(debug=args.debug, nocolors=args.no_colors, logfile=args.logfile)
    logger.success("======================================================")
    logger.success("    EVEN6 live monitor v0.1        @NeffIsBack        ")
    logger.success("======================================================")
    logger.print()

    auth_lm_hash = ""
    auth_nt_hash = ""
    if args.auth_hashes is not None:
        if ":" in args.auth_hashes:
            auth_lm_hash = args.auth_hashes.split(":")[0]
            auth_nt_hash = args.auth_hashes.split(":")[1]
        else:
            auth_nt_hash = args.auth_hashes

    msevenclass = MSEven6Trigger(logger, args)
    try:
        msevenclass.connect(
            username=args.auth_username,
            password=args.auth_password,
            domain=args.auth_domain,
            lmhash=auth_lm_hash,
            nthash=auth_nt_hash,
            target=args.dc_ip,
            doKerberos=args.use_kerberos,
            dcHost=args.kdcHost,
            aesKey=args.aesKey,
            pipe="eventlog"
        )
    except DCERPCException as e:
        logger.error(f"Failed to connect to the domain controller: {e}")
        return

    msevenclass.watch(args.channel, args.event_id, args.grep)


if __name__ == "__main__":
    main()

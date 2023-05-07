import logging
import threading

from socket import socket, AF_INET, SOCK_DGRAM, SOCK_STREAM
from subprocess import run, PIPE
from re import compile
from ipaddress import IPv4Address, IPv4Interface
from time import sleep

from ttkbootstrap.scrolled import ScrolledText

from ttkbootstrap import BooleanVar

from pythonping import ping
from mac_vendor_lookup import MacLookup, BaseMacLookup
from ttkbootstrap.constants import END


class TkHandle(logging.Handler):
    def __init__(self, textbox: ScrolledText):
        formatter = logging.Formatter("[%(levelname)s] %(message)s")
        logging.Handler.__init__(self)
        self.textbox = textbox
        self.setFormatter(formatter)

    def emit(self, record):
        msg = self.format(record)

        def append():
            self.textbox.text.configure(state="normal")
            self.textbox.text.insert(END, msg + "\n")
            self.textbox.text.configure(state="disabled")
            self.textbox.text.see(END)

        self.textbox.after(0, append)


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
log_formatter = logging.Formatter("[%(levelname)s] %(message)s")
log_fileHandler = logging.FileHandler("netscan.log")
log_fileHandler.setLevel(logging.INFO)
log_fileHandler.setFormatter(log_formatter)
log_streamHandler = logging.StreamHandler()
log_streamHandler.setFormatter(log_formatter)
logger.addHandler(log_fileHandler)
logger.addHandler(log_streamHandler)

(
    RMAC_PATTERN,
    RE_NAME,
    RE_IP,
    RE_SUBNET,
    RE_MAC,
    RE_MACPATTERN,
    RE_IPPATTERN,
    RE_MACTYPE,
) = (
    compile(r"(([0-9a-fA-F]){2}[-:]){5}([0-9a-fA-F]){2}"),
    compile(r"Description"),
    compile(r"IPv4 Address"),
    compile(r"Subnet Mask"),
    compile(r"Physical Address"),
    compile(r"(([0-9a-fA-F]){2}[-:]){5}([0-9a-fA-F]){2}"),
    compile(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"),
    compile(r"dynamic"),
)

(
    RMAC_PATTERN_CN,
    RE_NAME_CN,
    RE_IP_CN,
    RE_SUBNET_CN,
    RE_MAC_CN,
    RE_MACPATTERN_CN,
    RE_IPPATTERN_CN,
    RE_MACTYPE_CN,
) = (
    compile(r"(([0-9a-fA-F]){2}[-:]){5}([0-9a-fA-F]){2}"),
    compile(r"Description"),
    compile(r"IPv4 Address"),
    compile(r"Subnet Mask"),
    compile(r"Physical Address"),
    compile(r"(([0-9a-fA-F]){2}[-:]){5}([0-9a-fA-F]){2}"),
    compile(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"),
    compile(r"dynamic"),
)


class NetScanner:
    def __init__(self, vendorListPath: str = "None"):
        logger.debug("initializing scanner")
        self.maclookup = MacLookup()
        if vendorListPath != "None":
            logger.debug("check mac address vendor list file")
            try:
                BaseMacLookup.cache_path = vendorListPath
            except:
                logger.exception("unable to local vendor list file")
            else:
                logger.debug(f"found vendor list in {vendorListPath}")

        self.is_scanning = False
        self.active_interface = {}
        self.interface_list = []
        self.responded_hosts = []
        self.ip_mac_map = {}

        self.settings = {
            "MacLookup": BooleanVar(),
            "httpScan": BooleanVar(),
            "httpsScan": BooleanVar(),
            "SkipPing": BooleanVar(),
        }

    def start_pings(self):
        ## check skip options
        if self.settings["SkipPing"].get():
            logger.info("skip pings")
        else:
            thread = threading.Thread(target=self._pingicmps)
            thread.start()
            thread.join()
            # self._pingicmps()
            logger.info("all ping finished")

        ## run web port scan
        if self.settings["httpScan"].get() or self.settings["httpsScan"].get():
            logger.info("scanning web service")
            thread = threading.Thread(target=self.check_tcp)
            thread.start()
            thread.join()
            # self.check_tcp()

        ## run mac lookup
        if self.settings["MacLookup"].get():
            logger.info("check mac address and vendor")
            thread = threading.Thread(target=self.check_macvendor)
            thread.start()
            thread.join()
            # self.check_macvendor()

        ## sort outputs
        self.responded_hosts = sorted(
            self.responded_hosts, key=lambda d: d["ipv4_addr"].packed
        )

        ## unlock gui
        self.is_scanning = False

    def _pingicmps(self):
        thread_queue = []
        for ip in self.active_interface["ipv4_interface"].network.hosts():
            thread = threading.Thread(target=self.ping_icmp, args=(ip,))
            thread.start()
            thread_queue.append(thread)
            sleep(0.01)
        for thread in thread_queue:
            thread.join()

    def ping_icmp(self, ipv4_addr: IPv4Address):
        ip = ipv4_addr.exploded
        logger.debug(f"pinging {ip}...")
        if ping(ip, timeout=1).success():
            logger.debug(f"{ip} responded")
            for host in self.responded_hosts:
                if ipv4_addr == host["ipv4_addr"]:
                    logger.info(f"{ip} already in reponded list")
                    return
            logger.info(f"{ip} responded, add to reponded list")
            self.responded_hosts.append(
                {
                    "ipv4_addr": ipv4_addr,
                    "http": False,
                    "https": False,
                    "mac_address": "Unknow",
                    "vendor": "Unknow",
                }
            )

    def clean_respondedList(self):
        self.responded_hosts = []
        logger.info("clean responded list")

    def check_tcp(self):
        for _ in range(len(self.responded_hosts)):
            host = self.responded_hosts.pop(0)
            ip = host["ipv4_addr"].exploded

            if self.settings["httpScan"].get():
                try:
                    sock = socket(AF_INET, SOCK_STREAM)
                    sock.settimeout(0.5)
                    sock.connect((ip, 80))
                    sock.settimeout(None)
                except:
                    logger.debug(f"{ip}:80 is close")
                    host["http"] = False
                else:
                    logger.info(f"http://{ip}:80 is open")
                    sock.close()
                    host["http"] = True

            if self.settings["httpsScan"].get():
                try:
                    sock = socket(AF_INET, SOCK_STREAM)
                    sock.settimeout(1)
                    sock.connect((ip, 443))
                    sock.settimeout(None)
                except:
                    logger.debug(f"{ip}:443 is close")
                    host["https"] = False
                else:
                    logger.info(f"https://{ip}:443 is open")
                    sock.close()
                    host["https"] = True

            self.responded_hosts.append(host)

    def check_macvendor(self):
        self.scan_arp()
        logger.info("get arp table")
        for _ in range(len(self.responded_hosts)):
            host = self.responded_hosts.pop(0)
            ip = host["ipv4_addr"].exploded
            if ip in self.ip_mac_map:
                mac = self.ip_mac_map[ip]
                vendor = self._check_vendor(mac)
                logger.info(f"{ip} vendor is {vendor}")
            elif ip == self.active_interface["ipv4_interface"].ip.exploded:
                mac = self.active_interface["mac_address"]
                vendor = self._check_vendor(mac)
                logger.info(f"{ip} vendor is {vendor}")
            else:
                mac = "Unknow"
                vendor = "Unknow"
                logger.info(f"can't found vendor of {ip}")
            host["mac_address"] = mac
            host["vendor"] = vendor
            self.responded_hosts.append(host)

    def _check_vendor(self, mac: str) -> str:
        try:
            vendor = self.maclookup.lookup(mac)
        except:
            return "Unknow"
        else:
            return vendor

    def get_interfaceStrList(self) -> list[str]:
        temp_list = [
            "No Interface",
        ]
        defip = get_defip()
        for interface in self.interface_list:
            ip = interface["ipv4_interface"].ip
            if defip == ip:
                temp_list[0] = f"{ip} --- {interface['interface']}"
            else:
                temp_list.append(f"{ip} --- {interface['interface']}")
        logger.debug("update interface to GUI")
        return temp_list

    def get_interfaceInfo(self) -> list[str]:
        temp_list = []
        for k, v in self.active_interface.items():
            temp_list.append(f"{k.replace('_',' ').capitalize()}:\n{v}\n")
        return temp_list

    def scan_interfaces(self):
        logger.debug("scanning interfaces on this device")
        runwincmd_ipconfig = str(self.__run_windowsCommand("ipconfig -all"))
        temp_list = self.__sort_ipconfig(runwincmd_ipconfig)
        self.interface_list = self.__filter_nonActiveInterface(temp_list)
        for nic in self.interface_list:
            logger.info(
                f"interface found: {nic['interface']} --> {nic['ipv4_interface']}"
            )

    def scan_arp(self):
        logger.debug("geting MAC address from ARP table")
        runwincmd_arp = str(self.__run_windowsCommand("arp -a"))
        self.ip_mac_map = self.__sort_arp(runwincmd_arp)

    def set_defaultActiveInterface(self):
        defaultinterface = get_defip()
        for interface in self.interface_list:
            if interface["ipv4_interface"].ip == defaultinterface:
                logger.debug(f"Set Default Interface to {defaultinterface}")
                self.active_interface = interface
                return
        # do something if not interface match

    def set_ActiveInterface(self, _ip: str):
        ip = _ip
        logger.debug(f"check if {ip} in interface list")
        for interface in self.interface_list:
            if interface["ipv4_interface"].ip.exploded == ip:
                logger.debug("found interface")
                self.active_interface = interface
                return
        logger.debug(f"cant found {ip} in interface list")

    @staticmethod
    def __run_windowsCommand(command: str):
        logger.debug(f"runnig window command {command}")
        try:
            output = run(command, stdout=PIPE, text=True)
        except:
            logger.exception("command failed")
        else:
            logger.debug("command suceeded")
            return output

    @staticmethod
    def __sort_ipconfig(input: str):
        logger.debug("sorting interfaces list")
        lines = input.split("\\n")
        interfaceList = []
        newInterface = {}

        for line in lines:
            line.strip()
            if len(line) == 0:
                continue
            if bool(RE_NAME.search(line)):
                if len(newInterface) > 0:
                    interfaceList.append(newInterface)
                newInterface = {}
                newInterface["interface"] = line.split(" :")[1].strip()
            elif bool(RE_IP.search(line)):
                newInterface["ipv4_addr"] = (
                    line.split(" :")[1].strip().replace("(Preferred)", "")
                )
            elif bool(RE_SUBNET.search(line)):
                newInterface["subnet_mask"] = line.split(" :")[1].strip()
            elif bool(RE_MAC.search(line)):
                newInterface["mac_address"] = line.split(" :")[1].strip()
        interfaceList.append(newInterface)
        # for interface in interfaceList:
        #     logger.debug(interface)
        return interfaceList

    @staticmethod
    def __filter_nonActiveInterface(interface_list: list):
        logger.debug("clean interfaces with out ipv4 address")
        temp_list = []
        for interface in interface_list:
            if "ipv4_addr" in interface:
                interface["ipv4_interface"] = IPv4Interface(
                    (interface["ipv4_addr"], interface["subnet_mask"])
                )
                del interface["subnet_mask"]
                del interface["ipv4_addr"]
                temp_list.append(interface)
        return temp_list

    @staticmethod
    def __sort_arp(input: str):
        logger.debug("sorting ARP table")
        lines = input.split("\\n")
        temp_dict = dict()
        for line in lines:
            line.strip()
            try:
                if bool(RE_MACTYPE.search(line)):
                    ip_temp = RE_IPPATTERN.search(line)
                    if ip_temp != None:
                        ip = ip_temp[0]
                    else:
                        ip = "Unknow"
                    mac_temp = RE_MACPATTERN.search(line)
                    if mac_temp != None:
                        mac = mac_temp[0]
                    else:
                        mac = "Unknow"
                    # ip = RE_IPPATTERN.search(line)[0]
                    # mac = RE_MACPATTERN.search(line)[0].upper()
                    temp_dict[ip] = mac
            except:
                logger.exception("failed to get mac address from ARP table")
        return temp_dict


def get_defip() -> IPv4Address:
    s = socket(AF_INET, SOCK_DGRAM)
    s.settimeout(0)
    try:
        s.connect(("10.254.254.254", 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = "127.0.0.1"
    finally:
        s.close()
    return IPv4Address(IP)


if __name__ == "__main__":
    app = NetScanner()
    app.check_tcp()
    app.check_macvendor()
    app.scan_interfaces()
    app.set_defaultActiveInterface()
    app.start_pings()

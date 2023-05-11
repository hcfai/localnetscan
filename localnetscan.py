import logging
import threading

from tkinter import filedialog
from os import _exit, path

from sys import exception, executable
from locale import getlocale
from re import compile
from time import strftime, localtime, sleep

import pyuac

from gui import tkgui
from scanner import netscanner

DIR_PATH = path.dirname(__file__)
NOTE = """Network Scanner for AV Technician v1.3_e
DO NOT use this software in public network.
Prefix small then 24 is not supported.
Only work on English and Tranditional Chinese
Click [OK!] if you agree to use this software in your own risk.


Included Moduls:
israel-dryer/ttkbootstrap
alessandromagg/pythonping
bauerj/mac_vendor_lookup
"""


def check_system():
    this_locale = str(getlocale()[0])

    if this_locale.startswith("English"):
        pass
    elif this_locale.startswith("Chinese (Traditional)"):
        netscanner.RE_NAME = compile(r"描述")
        netscanner.RE_IP = compile(r"IPv4 位址")
        netscanner.RE_SUBNET = compile(r"子網路遮罩")
        netscanner.RE_MAC = compile(r"實體位址")
        netscanner.RE_MACTYPE = compile(r"動態")
        netscanner.W_IP = "(偏好選項)"
    else:
        netscanner.logger.warn("ONLY WORK ON ENGLISH or CHINESE (TRANDITIONAL)")
        gui.messagebox.show_error(
            "Programe only works on English or Chinese (Traditional) system", "Error"
        )


def buttonFunc_popupConfirmYes():
    netscanner.logger.info(
        f"Program Start at {strftime('%Y/%m/%d - %H:%M:%S', localtime())}"
    )
    gui.deiconify()
    gui.popup.withdraw()
    app.scan_interfaces()
    app.set_defaultActiveInterface()
    gui.update_interfaceOptions(app.get_interfaceStrList())
    gui.update_interfaceInfo(app.get_interfaceInfo())
    if isAdmin:
        gui.update_netshInfo(app.get_netshInfo())


def buttonFunc_popupConfirmNo():
    gui.destroy()
    sleep(1)
    _exit(0)


def buttonFunc_startPing():
    current_time = f"NEW SCAN START AT {strftime('%Y/%m/%d - %H:%M:%S', localtime())}"
    gui.print_textbox(current_time + "\n")
    netscanner.logger.info(current_time)

    if app.active_interface == {}:
        msg_1 = "Not interface selected"
        netscanner.logger.info(msg_1)
        gui.messagebox.show_info(msg_1)
        return

    if app.active_interface["ipv4_interface"].ip.is_global:
        msg_2 = "Non private IP interface. scan not supported"
        netscanner.logger.error(msg_2)
        gui.messagebox.show_error(msg_2)
        return

    if app.active_interface["ipv4_interface"].network.prefixlen < 24:
        msg_3 = "Network prefix small than 24, scan not supported"
        netscanner.logger.error(msg_3)
        gui.messagebox.show_error(msg_3)
        return

    thread = threading.Thread(target=app.start_pings)
    thread.start()

    app.is_scanning = True
    gui.lock_gui()
    thread_2 = threading.Thread(target=wait_for_scan)
    thread_2.start()


def wait_for_scan():
    sleep(1)
    while True:
        if app.is_scanning:
            sleep(1)
        else:
            print_report()
            gui.unlock_gui()
            break


def watch_netsh_config():
    this = app.get_interfaceInfo()
    while True:
        sleep(5)
        new = app.get_interfaceInfo()
        if this == new:
            gui.update_netshInfo(app.get_netshInfo())
            app.scan_interfaces()
            gui.update_interfaceOptions(app.get_interfaceStrList())
            gui.update_interfaceInfo(new)
            break


def print_report():
    for host in app.responded_hosts:
        gui.print_textbox(f"{host['ipv4_addr']} is up")
        if host["mac_address"] != "Unknow":
            gui.print_textbox(f"--> {host['mac_address']} --> {host['vendor']} \n")
        else:
            gui.print_textbox("\n")

    gui.clean_webbutton()
    for host in app.responded_hosts:
        ip = host["ipv4_addr"]
        vendor = host["vendor"]
        if host["http"] or host["https"]:
            gui.print_textbox(f"----- \n{vendor} - {ip} active web service: \n")
        else:
            continue
        if host["http"]:
            gui.print_textbox(f"http://{ip}:80 \n")
        if host["https"]:
            gui.print_textbox(f"http://{ip}:443 \n")
        gui.create_webbutton(ip, vendor, host["http"], host["https"])


def buttonFunc_rescanNetwork():
    netscanner.logger.info("Rescan network interfaces")
    app.scan_interfaces()
    app.set_defaultActiveInterface()
    gui.update_interfaceOptions(app.get_interfaceStrList())
    gui.update_interfaceInfo(app.get_interfaceInfo())
    if isAdmin:
        gui.update_netshInfo(app.get_netshInfo())


def buttonFunc_savetxt():
    try:
        exepath = path.dirname(executable)
        with open(
            filedialog.asksaveasfilename(
                initialdir=exepath,
                title="output.txt",
                defaultextension=".txt",
            ),
            "w",
        ) as f:
            f.write(gui.console_textbox.text.get(1.0, "end"))

    except:
        pass
    else:
        netscanner.logger.info("file saved")


def buttonFunc_cleanConsole():
    app.responded_hosts = []
    gui.clean_text(gui.console_textbox.text)
    netscanner.logger.info("Clean responded host.")


def buttonFunc_netshRefresh():
    netscanner.logger.info("Get Netsh Static")
    gui.update_netshInfo(app.get_netshInfo())


def buttonFunc_netshSetDHCP():
    netscanner.logger.info(f"Set {app.active_interface['netsh']} to DHCP")
    app.set_ActiveInterface_DHCP()
    thread = threading.Thread(target=watch_netsh_config)
    thread.start()


def buttonFunc_netshSetStaic_1():
    ip, sn, gw = gui.netsh_static_1.get_static_config()
    netscanner.logger.info(f"Set {app.active_interface['netsh']} to {ip, sn, gw}")
    app.set_ActiveInterface_staticIP(ip, sn, gw)
    thread = threading.Thread(target=watch_netsh_config)
    thread.start()


def buttonFunc_netshSetStaic_2():
    ip, sn, gw = gui.netsh_static_1.get_static_config()
    netscanner.logger.info(f"Set {app.active_interface['netsh']} to {ip, sn, gw}")
    app.set_ActiveInterface_staticIP(ip, sn, gw)
    thread = threading.Thread(target=watch_netsh_config)
    thread.start()


def menuFunc_changeActiveInterface(*_):
    ip = gui.om_optionVar.get().split(" --- ")[0]
    app.set_ActiveInterface(ip)
    gui.update_interfaceInfo(app.get_interfaceInfo())
    if isAdmin:
        gui.update_netshInfo(app.get_netshInfo())


def initGUItext():
    gui.popup_textbox.insert("end", NOTE)
    gui.popup_textbox.configure(state="disabled")


def initGUIfunctions():
    gui.popup_button.configure(command=buttonFunc_popupConfirmYes)
    gui.popup_button2.configure(command=buttonFunc_popupConfirmNo)
    gui.popup.protocol("WM_DELETE_WINDOW", buttonFunc_popupConfirmNo)
    gui.protocol("WM_DELETE_WINDOW", buttonFunc_popupConfirmNo)
    gui.button_1.configure(command=buttonFunc_startPing)
    gui.button_2.configure(command=buttonFunc_rescanNetwork)
    gui.button_3.configure(command=buttonFunc_cleanConsole)
    gui.button_4.configure(command=buttonFunc_savetxt)
    gui.checkbutton_1.configure(variable=app.settings["MacLookup"])
    app.settings["MacLookup"].set(True)
    gui.checkbutton_2.configure(variable=app.settings["httpScan"])
    app.settings["httpScan"].set(True)
    gui.checkbutton_3.configure(variable=app.settings["httpsScan"])
    app.settings["httpsScan"].set(True)
    gui.checkbutton_4.configure(variable=app.settings["SkipPing"])
    gui.om_optionVar.trace("w", menuFunc_changeActiveInterface)
    gui.button_5.configure(command=buttonFunc_test)
    gui.button_6.configure(command=buttonFunc_test_2)
    # gui.button_5.forget()
    # gui.button_6.forget()


def init_netsh():
    if isAdmin:
        gui.isAdmin = True
        app.isAdmin = True
        gui.create_netsh_admin()
        gui.netsh_labelframe_netshOutput.configure(text="Netsh Output")
        gui.netsh_button_1.configure(text="Refresh", command=buttonFunc_netshRefresh)
        gui.netsh_button_2.configure(text="Set DHCP", command=buttonFunc_netshSetDHCP)
        gui.netsh_static_1.button.configure(command=buttonFunc_netshSetStaic_1)
        gui.netsh_static_2.button.configure(command=buttonFunc_netshSetStaic_2)
        thread = threading.Thread(target=watch_netsh_config)
        thread.start()

    else:
        netscanner.logger.info("Not administrator")
        gui.create_netsh_noAdmin()
        gui.netsh_label.configure(
            text="To use interface control, you mush run this application in Administrator Mode"
        )
        gui.netsh_button.configure(text="Restart to Administrator Mode")
        gui.netsh_button.configure(command=rerun_admin)


def test_func():
    pass


def rerun_admin():
    gui.destroy()
    pyuac.runAsAdmin()
    sleep(1)
    _exit(0)


def buttonFunc_test():
    print("Run debug function 1")
    pass


def buttonFunc_test_2():
    print("Run debug function 2")
    thread = threading.Thread(target=watch_netsh_config)
    thread.start()
    pass


if __name__ == "__main__":
    isAdmin = pyuac.isUserAdmin()
    # load GUI
    gui = tkgui.Tkgui(title="Network Scaner v1.3_e", dirpath=DIR_PATH)

    # log handler, scanner to gui
    log_tkhandle = netscanner.TkHandle(gui.console_textbox2)
    log_tkhandle.setLevel(logging.INFO)
    netscanner.logger.addHandler(log_tkhandle)
    check_system()

    # load backend
    app = netscanner.NetScanner(vendorListPath=path.join(DIR_PATH, "mac_vendor.txt"))

    # link gui to backend
    initGUItext()
    initGUIfunctions()
    init_netsh()

    # test_func()

    gui.mainloop()

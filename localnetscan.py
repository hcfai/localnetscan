import logging
import threading

from tkinter import filedialog
from os import _exit, path
from platform import system
from sys import executable
from locale import getlocale

from time import strftime, localtime, sleep


from gui import tkgui
from scanner import netscanner

DIR_PATH = path.dirname(__file__)
NOTE = """Network Scanner for AV Technician v1.1
DO NOT use this software in  pulbic network.
Click [OK!] if you agree to not use this software in your own risk.

Included Moduls:
israel-dryer/ttkbootstrap
alessandromagg/pythonping
bauerj/mac_vendor_lookup
"""


def check_system():
    this_system = system()
    this_locale = str(getlocale()[0])

    if this_locale.startswith("English"):
        pass
    else:
        netscanner.logger.warn("ONLY WORK ON ENGLISH")
        gui.messagebox.show_error("Programe only work on English system", "Error")
    return (this_system, this_locale)


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
    check_system()


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


def menuFunc_changeActiveInterface(*_):
    ip = gui.om_optionVar.get().split(" --- ")[0]
    app.set_ActiveInterface(ip)
    gui.update_interfaceInfo(app.get_interfaceInfo())


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
    gui.button_5.configure(command=buttonFunc_test)
    gui.checkbutton_1.configure(variable=app.settings["MacLookup"])
    app.settings["MacLookup"].set(True)
    gui.checkbutton_2.configure(variable=app.settings["httpScan"])
    app.settings["httpScan"].set(True)
    gui.checkbutton_3.configure(variable=app.settings["httpsScan"])
    app.settings["httpsScan"].set(True)
    gui.checkbutton_4.configure(variable=app.settings["SkipPing"])
    gui.om_optionVar.trace("w", menuFunc_changeActiveInterface)


def test_func():
    pass


def buttonFunc_test():
    pass


if __name__ == "__main__":
    # load GUI
    gui = tkgui.Tkgui(title="Network Scaner v1.1", dirpath=DIR_PATH)

    # log handler, scanner to gui
    log_tkhandle = netscanner.TkHandle(gui.console_textbox2)
    log_tkhandle.setLevel(logging.INFO)
    netscanner.logger.addHandler(log_tkhandle)

    # load backend
    app = netscanner.NetScanner(vendorListPath=path.join(DIR_PATH, "mac_vendor.txt"))

    # link gui to backend
    initGUItext()
    initGUIfunctions()

    # test_func()

    gui.mainloop()

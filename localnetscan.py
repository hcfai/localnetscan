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
NOTE = """Network Scanner for AV Technician v1.0
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

    if this_system == "Windows":
        pass
    else:
        pass

    if this_locale.startswith("English"):
        pass
    else:
        netscanner.logger.warn("ONLY WORK ON ENGLISH")
        pass
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


def buttonFunc_popupConfirmNo():
    gui.destroy()
    sleep(1)
    _exit(0)


def buttonFunc_startPing():
    current_time = f"NEW SCAN START AT {strftime('%Y/%m/%d - %H:%M:%S', localtime())}"
    gui.print_textbox(current_time + "\n")
    netscanner.logger.info(current_time)
    if app.active_interface == {}:
        netscanner.logger.info("not interface selected")
        return
    thread = threading.Thread(target=app.start_pings, args=(gui, gui.print_textbox))
    thread.start()
    app.is_scanning = True
    gui.lock_gui()


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
        # netscanner.logger.exception("failed to save")
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
    gui.checkbutton_1.configure(variable=app.settings["MacLookup"])
    app.settings["MacLookup"].set(True)
    gui.checkbutton_2.configure(variable=app.settings["httpScan"])
    app.settings["httpScan"].set(True)
    gui.checkbutton_3.configure(variable=app.settings["httpsScan"])
    app.settings["httpsScan"].set(True)
    gui.checkbutton_4.configure(variable=app.settings["SkipPing"])
    gui.om_optionVar.trace("w", menuFunc_changeActiveInterface)


if __name__ == "__main__":
    # load GUI
    gui = tkgui.Tkgui(title="Network Scaner v1.0")

    system_info = check_system()
    if system_info[0] == "Windows":
        pass

    gui.iconbitmap(path.join(DIR_PATH, "icon.ico"))
    gui.popup.iconbitmap(path.join(DIR_PATH, "icon.ico"))

    # log handler, scanner to gui
    log_tkhandle = netscanner.TkHandle(gui.console_textbox2)
    log_tkhandle.setLevel(logging.INFO)
    netscanner.logger.addHandler(log_tkhandle)

    # load backend
    app = netscanner.NetScanner(vendorListPath=path.join(DIR_PATH, "mac_vendor.txt"))

    # link gui to backend
    initGUItext()
    initGUIfunctions()

    gui.mainloop()

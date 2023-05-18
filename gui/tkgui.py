import webbrowser
import ttkbootstrap as ttk
from os import path
from ttkbootstrap.dialogs.dialogs import Messagebox
from ttkbootstrap.scrolled import ScrolledText, ScrolledFrame


class Tkgui(ttk.Window):
    def __init__(self, *args, title: str = "Network Scaner", dirpath: str, **kwargs):
        super().__init__(*args, **kwargs)
        screensize = (
            f"{int(self.winfo_screenwidth()*0.5)}x{int(self.winfo_screenheight()*0.6)}"
        )
        self.create_popup(dirpath)
        self.title(title)
        self.geometry(screensize)
        self.minsize(720, 700)
        self.withdraw()
        self.iconbitmap(path.join(dirpath, "icon.ico"))
        self.messagebox = Messagebox()

        self.main_frame = ttk.Frame(self)
        self.main_frame.pack(side="top", anchor="n", expand=True, fill="both")
        self.webNodeList = []
        self.isAdmin = False

        self.layout_console()
        self.layout_sidebar()

    def layout_console(self):
        self.frame_console = ttk.Frame(self.main_frame)
        self.sublayout_notebook()
        self.sublayout_infomationConsole()
        self.sublayout_scanOptions()
        self.sublayout_scanControl()

        self.frame_console.pack(
            side="left", anchor="w", padx=10, pady=10, expand=True, fill="both"
        )

    def sublayout_notebook(self):
        self.notebook_main = ttk.Notebook(self.frame_console, bootstyle="primary")
        # Output Terminal
        self.noteframe_terminal = ttk.Frame(None)
        self.console_textbox = ScrolledText(self.noteframe_terminal, padding=0)
        self.console_textbox.text.configure(height=12, state="disabled")
        self.console_textbox.pack(expand=True, fill="both")

        # website button page
        self.noteframe_webPages = ttk.Frame(None)
        self.noteframe_helper_webPages = ScrolledFrame(self.noteframe_webPages)
        self.noteframe_helper_webPages.pack(expand=True, fill="both")

        # netsh page
        self.noteframe_netsh = ttk.Frame(None)

        # add frame to notebook
        self.notebook_main.add(self.noteframe_terminal, text="Terminal  ")
        self.notebook_main.add(self.noteframe_webPages, text="Web Serivces")
        self.notebook_main.add(self.noteframe_netsh, text="Interface Control")
        self.notebook_main.pack(expand=True, fill="both")

    def sublayout_infomationConsole(self):
        self.console_textbox2 = ScrolledText(self.frame_console)
        self.console_textbox2.text.configure(height=12)
        self.console_textbox2.pack(fill="x")
        self.progressbar = ttk.Progressbar(self.frame_console, mode="determinate")
        self.progressbar.pack(fill="x", pady=(5, 0))

    def sublayout_scanOptions(self):
        self.subframe_scanOptions = ttk.Frame(self.frame_console, height=4)
        self.checkbutton_1 = ttk.Checkbutton(
            self.subframe_scanOptions,
            bootstyle="round-toggle",
            text="MAC Address Lookup",
        )
        self.checkbutton_2 = ttk.Checkbutton(
            self.subframe_scanOptions, bootstyle="round-toggle", text="HTTP Scan"
        )
        self.checkbutton_3 = ttk.Checkbutton(
            self.subframe_scanOptions, bootstyle="round-toggle", text="HTTPS Scan"
        )
        self.checkbutton_4 = ttk.Checkbutton(
            self.subframe_scanOptions, bootstyle="round-toggle", text="Skip ICMP"
        )
        self.checkbutton_1.pack(side="left", anchor="w", padx=(10, 0))
        self.checkbutton_2.pack(side="left", anchor="w", padx=(10, 0))
        self.checkbutton_3.pack(side="left", anchor="w", padx=(10, 0))
        self.checkbutton_4.pack(side="left", anchor="w", padx=(10, 0))
        self.subframe_scanOptions.pack(anchor="w", pady=(10, 0))

    def sublayout_scanControl(self):
        self.subframe_scanControl = ttk.Frame(self.frame_console, height=4)
        self.button_1 = ttk.Button(self.subframe_scanControl, text="Start Scan")
        self.button_2 = ttk.Button(self.subframe_scanControl, text="Refresh Network")
        self.button_3 = ttk.Button(self.subframe_scanControl, text="Clean All")
        self.button_4 = ttk.Button(self.subframe_scanControl, text="Save to .txt")
        self.button_1.pack(side="left", anchor="w", padx=(10, 0))
        self.button_2.pack(side="left", anchor="w", padx=(10, 0))
        self.button_3.pack(side="left", anchor="w", padx=(10, 0))
        self.button_4.pack(side="left", anchor="w", padx=(10, 0))
        self.button_5 = ttk.Button(self.subframe_scanControl, text="Debug")
        self.button_5.pack(side="left", anchor="w", padx=(10, 0))
        self.button_6 = ttk.Button(self.subframe_scanControl, text="Debug")
        self.button_6.pack(side="left", anchor="w", padx=(10, 0))
        self.subframe_scanControl.pack(anchor="w", pady=(10, 0))

    def layout_sidebar(self):
        self.frame_sidebar = ttk.Frame(self.main_frame)
        self.sidebar_label = ttk.Label(self.frame_sidebar, text="Interface Info")
        self.sidebar_label.pack(anchor="n")

        self.sidebar_textbox = ttk.Text(
            self.frame_sidebar, height=16, width=40, state="disabled"
        )
        self.sidebar_textbox.pack(anchor="n", pady=(10, 0))

        self.sidebar_label2 = ttk.Label(self.frame_sidebar, text="Select Interface")
        self.sidebar_label2.pack(anchor="n", pady=(10, 0))

        self.om_optionVar = ttk.StringVar()
        self.om_optionVar.set("Select Interface")
        self.sidebar_optionMenu = ttk.Menubutton(
            self.frame_sidebar,
            width=26,
            textvariable=self.om_optionVar,
        )
        self.om_options = ttk.Menu(self.sidebar_optionMenu, tearoff=0)
        self.sidebar_optionMenu["menu"] = self.om_options
        self.sidebar_optionMenu.pack(side="bottom", anchor="n", pady=(10, 0))

        self.frame_sidebar.pack(anchor="e", padx=(0, 10), pady=10, fill="y")

    def update_interfaceOptions(self, nics):
        self.om_options.delete(0, "end")
        for nic in nics:
            self.om_options.add_radiobutton(
                label=nic, value=nic, variable=self.om_optionVar
            )
        self.sidebar_optionMenu["menu"] = self.om_options
        self.om_optionVar.set(nics[0])

    def update_interfaceInfo(self, info: list[str]):
        self.sidebar_textbox.configure(state="normal")
        self.sidebar_textbox.delete("1.0", "end")
        for line in info:
            self.sidebar_textbox.insert("end", line + "\n")
        self.sidebar_textbox.configure(state="disabled")

    def print_textbox(self, text: str):
        self.console_textbox.text.configure(state="normal")
        self.console_textbox.text.insert("end", text)
        self.console_textbox.text.configure(state="disabled")

    def clean_webbutton(self):
        if len(self.webNodeList) > 0:
            for node in self.webNodeList:
                node.destroy()

    def lock_gui(self):
        self.button_1.configure(state="disabled")
        self.button_2.configure(state="disabled")
        self.button_3.configure(state="disabled")
        self.button_4.configure(state="disabled")
        self.checkbutton_1.configure(state="disabled")
        self.checkbutton_2.configure(state="disabled")
        self.checkbutton_3.configure(state="disabled")
        self.checkbutton_4.configure(state="disabled")
        self.sidebar_optionMenu.configure(state="disabled")
        self.progressbar.start(20)

    def unlock_gui(self):
        self.button_1.configure(state="normal")
        self.button_2.configure(state="normal")
        self.button_3.configure(state="normal")
        self.button_4.configure(state="normal")
        self.checkbutton_1.configure(state="normal")
        self.checkbutton_2.configure(state="normal")
        self.checkbutton_3.configure(state="normal")
        self.checkbutton_4.configure(state="normal")
        self.sidebar_optionMenu.configure(state="normal")
        self.progressbar.stop()

    def create_popup(self, dirpath):
        screen_width = int(self.winfo_screenwidth())
        screen_height = int(self.winfo_screenheight())
        screensize = f"{int(screen_width*0.3)}x{int(screen_height*0.25)}+{int(screen_width*0.3)}+{int(screen_height*0.3)}"
        self.popup = ttk.Toplevel(title="Wellcome")
        self.popup.geometry(screensize)
        self.popup.resizable(False, False)
        self.popup.iconbitmap(path.join(dirpath, "icon.ico"))
        self.popup_textbox = ttk.Text(self.popup, height=1)
        self.popup_textbox.pack(padx=20, pady=20, expand=True, fill="y")
        self.frame_popup = ttk.Frame(self.popup)
        self.popup_button = ttk.Button(self.frame_popup, width=16, text="OK!")
        self.popup_button.pack(side="left", padx=20)
        self.popup_button2 = ttk.Button(self.frame_popup, width=16, text="NO THANKS")
        self.popup_button2.pack(side="left", padx=20)
        self.frame_popup.pack(side="top", padx=20, pady=(0, 10))

    def create_webbutton(self, web: str, text: str, http: bool, https: bool):
        self.newLabelFrame = ttk.LabelFrame(self.noteframe_helper_webPages, text=text)
        if http:
            self.newButton = ttk.Button(
                self.newLabelFrame,
                text=f"http://{web}:80",
                command=lambda: self.open_website(web, False),
            )
            self.newButton.pack(side="left", anchor="w", padx=10, pady=10)
        if https:
            self.newButton = ttk.Button(
                self.newLabelFrame,
                text=f"https://{web}:443",
                command=lambda: self.open_website(web, True),
            )
            self.newButton.pack(side="left", anchor="w", padx=10, pady=10)
        self.webNodeList.append(self.newLabelFrame)
        self.newLabelFrame.pack(padx=(0, 30), fill="x")

    def create_netsh_noAdmin(self):
        self.netsh_label = ttk.Label(self.noteframe_netsh)
        self.netsh_button = ttk.Button(self.noteframe_netsh)
        self.netsh_label.pack(pady=(100, 10))
        self.netsh_button.pack()
        pass

    def create_netsh_admin(self):
        self.noteframe_helper_netsh = ScrolledFrame(self.noteframe_netsh)
        self.noteframe_helper_netsh.pack(expand=True, fill="both")

        self.netsh_labelframe_netshOutput = ttk.LabelFrame(
            self.noteframe_helper_netsh, padding=0
        )
        self.netsh_labelframe_netshOutput.pack(padx=20, fill="x")
        self.netsh_label_1 = ttk.Label(
            self.netsh_labelframe_netshOutput, wraplength=600
        )
        self.netsh_label_1.pack(padx=20, fill="both")
        self.netsh_label_1 = ttk.Label(
            self.netsh_labelframe_netshOutput, wraplength=600
        )
        self.netsh_label_1.pack(padx=20, pady=5, fill="x")

        self.netsh_frame_options = ttk.Frame(self.netsh_labelframe_netshOutput)
        self.netsh_frame_options.pack(padx=20, fill="x")
        self.netsh_button_1 = ttk.Button(self.netsh_frame_options, text="button 1")
        self.netsh_button_1.pack(side="left", padx=5, pady=(0, 10))
        self.netsh_button_2 = ttk.Button(self.netsh_frame_options, text="button 2")
        self.netsh_button_2.pack(side="left", padx=5, pady=(0, 10))

        self.netsh_static_1 = Netsh_StaticConfig(self.noteframe_helper_netsh)
        self.netsh_static_1.pack(padx=20, pady=(0, 5), fill="x")
        self.netsh_static_2 = Netsh_StaticConfig(self.noteframe_helper_netsh)
        self.netsh_static_2.pack(padx=20, pady=(0, 5), fill="x")

    def update_netshInfo(self, lines: list[str]):
        if not self.isAdmin:
            return
        if len(lines) == 0:
            self.netsh_label_1.configure(text="Please Select an interface")
            return
        text = ""
        for line in lines[2:-2]:
            if line != "":
                text = text + f"{line}\n"
        self.netsh_label_1.configure(text=text)

    @staticmethod
    def clean_text(textbox):
        textbox.configure(state="normal")
        textbox.delete("1.0", "end")
        textbox.configure(state="disabled")

    @staticmethod
    def open_website(web: str, ssl: bool):
        if ssl:
            webbrowser.open(f"https://{web}:443")
        else:
            webbrowser.open(f"http://{web}:80")


class Netsh_StaticConfig(ttk.LabelFrame):
    def __init__(self, parent, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self.padding = 0
        self.ip = ttk.StringVar()
        self.subnet = ttk.StringVar()
        self.gateway = ttk.StringVar()
        self.ip.set("192.168.1.1")
        self.subnet.set("255.255.255.0")
        self.gateway.set("")

        self.label_ip = ttk.Label(self, text="IP Address")
        self.label_subnet = ttk.Label(self, text="Subnet Mask")
        self.label_gateway = ttk.Label(self, text="Default Gateway")
        self.label_ip.grid(column=0, row=0, padx=10, pady=10)
        self.label_subnet.grid(column=1, row=0, padx=10, pady=10)
        self.label_gateway.grid(column=2, row=0, padx=10, pady=10)

        self.entry_ip = ttk.Entry(self, textvariable=self.ip)
        self.entry_subnet = ttk.Entry(self, textvariable=self.subnet)
        self.entry_gateway = ttk.Entry(self, textvariable=self.gateway)
        self.entry_ip.grid(column=0, row=1, padx=10, pady=10)
        self.entry_subnet.grid(column=1, row=1, padx=10, pady=10)
        self.entry_gateway.grid(column=2, row=1, padx=10, pady=10)

        self.button = ttk.Button(
            self,
            text="Set",
            width=10,
        )
        self.button.grid(column=3, row=1, padx=10, pady=10)

        # self.button_del = ttk.Button(
        #     self, text="Del", width=10, command=self.del_this_config
        # )
        # self.button_del.grid(column=4, row=1, padx=10, pady=10)

    def get_static_config(self):
        # netsh = [self.ip.get(), self.subnet.get(), self.gateway.get()]
        # print(netsh)
        # return netsh
        return self.ip.get(), self.subnet.get(), self.gateway.get()

    def del_this_config(self):
        self.forget()
        self.destroy()


if __name__ == "__main__":
    pass

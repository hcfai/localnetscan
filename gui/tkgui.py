import ttkbootstrap as ttk
from ttkbootstrap.scrolled import ScrolledText


class Tkgui(ttk.Window):
    def __init__(self, *args, title: str = "Network Scaner", **kwargs):
        super().__init__(*args, **kwargs)
        screensize = (
            f"{int(self.winfo_screenwidth()*0.5)}x{int(self.winfo_screenheight()*0.6)}"
        )
        print(screensize)
        self.create_popup()
        self.title(title)
        # self.geometry("1080x700")
        self.geometry(screensize)
        self.minsize(720, 700)
        self.withdraw()

        # self.progressbar = ttk.Progressbar(self, mode="indeterminate")
        # self.progressbar.start(20)
        # self.progressbar.pack(side="bottom", anchor="s", expand=True, fill="x")

        self.layout_console()
        self.layout_sidebar()

    def layout_console(self):
        self.frame_console = ttk.Frame(self)
        self.console_label = ttk.Label(self.frame_console, text="Output Console")
        self.console_label.pack(anchor="n")
        self.console_textbox = ScrolledText(self.frame_console)
        self.console_textbox.text.configure(height=12, state="disabled")
        self.console_textbox.pack(anchor="n", pady=(10, 0), expand=True, fill="both")
        self.console_textbox2 = ScrolledText(self.frame_console)
        self.console_textbox2.text.configure(height=12)
        self.console_textbox2.pack(anchor="n", pady=(10, 0), fill="x")
        self.sublayout_scanOptions()
        self.sublayout_scanControl()
        self.frame_console.pack(
            side="left", anchor="w", padx=10, pady=10, expand=True, fill="both"
        )

    def sublayout_scanOptions(self):
        self.frame_scanOptions = ttk.Frame(self.frame_console, height=4)
        self.checkbutton_1 = ttk.Checkbutton(
            self.frame_scanOptions, bootstyle="round-toggle", text="MAC Address Lookup"
        )
        self.checkbutton_2 = ttk.Checkbutton(
            self.frame_scanOptions, bootstyle="round-toggle", text="HTTP Scan"
        )
        self.checkbutton_3 = ttk.Checkbutton(
            self.frame_scanOptions, bootstyle="round-toggle", text="HTTPS Scan"
        )
        self.checkbutton_4 = ttk.Checkbutton(
            self.frame_scanOptions, bootstyle="round-toggle", text="Skip ICMP"
        )
        # self.checkbutton_var = {"MacLookup": ttk.BooleanVar()}
        self.checkbutton_1.pack(side="left", anchor="w", padx=(10, 0))
        # self.checkbutton_1.configure(variable=self.checkbutton_var["MacLookup"])
        self.checkbutton_2.pack(side="left", anchor="w", padx=(10, 0))
        self.checkbutton_3.pack(side="left", anchor="w", padx=(10, 0))
        self.checkbutton_4.pack(side="left", anchor="w", padx=(10, 0))
        self.frame_scanOptions.pack(anchor="nw", pady=(10, 0))

    def sublayout_scanControl(self):
        self.frame_scanControl = ttk.Frame(self.frame_console, height=4)
        self.button_1 = ttk.Button(self.frame_scanControl, text="Start Scan")
        self.button_2 = ttk.Button(self.frame_scanControl, text="Refresh Network")
        self.button_3 = ttk.Button(self.frame_scanControl, text="Clean All")
        self.button_4 = ttk.Button(self.frame_scanControl, text="Save to .txt")
        self.button_1.pack(side="left", anchor="w", padx=(10, 0))
        self.button_2.pack(side="left", anchor="w", padx=(10, 0))
        self.button_3.pack(side="left", anchor="w", padx=(10, 0))
        self.button_4.pack(side="left", anchor="w", padx=(10, 0))
        self.frame_scanControl.pack(anchor="nw", pady=(10, 0))

    def layout_sidebar(self):
        self.frame_sidebar = ttk.Frame(self)
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

    def create_popup(self):
        screen_width = int(self.winfo_screenwidth())
        screen_height = int(self.winfo_screenheight())
        screensize = f"{int(screen_width*0.3)}x{int(screen_height*0.25)}+{int(screen_width*0.3)}+{int(screen_height*0.3)}"
        self.popup = ttk.Toplevel(title="Wellcome")
        # self.popup.geometry("500x260+200+200")
        self.popup.geometry(screensize)
        self.popup.resizable(False, False)
        self.popup_textbox = ttk.Text(self.popup, height=1)
        self.popup_textbox.pack(padx=20, pady=20, expand=True, fill="y")
        self.frame_popup = ttk.Frame(self.popup)
        self.popup_button = ttk.Button(self.frame_popup, width=16, text="OK!")
        self.popup_button.pack(side="left", padx=20)
        self.popup_button2 = ttk.Button(self.frame_popup, width=16, text="NO THANKS")
        self.popup_button2.pack(side="left", padx=20)
        self.frame_popup.pack(side="top", padx=20, pady=(0, 10))

    def print_textbox(self, text: str):
        self.console_textbox.text.configure(state="normal")
        self.console_textbox.text.insert("end", text)
        self.console_textbox.text.configure(state="disabled")

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

    @staticmethod
    def clean_text(textbox):
        textbox.configure(state="normal")
        textbox.delete("1.0", "end")
        textbox.configure(state="disabled")


if __name__ == "__main__":
    pass

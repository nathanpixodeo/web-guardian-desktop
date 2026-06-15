import os
import json
import customtkinter as ctk
from .ui.main_window import MainWindow


class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title('WebGuardian — Security Scanner')
        self.geometry('1160x780')
        self.minsize(920, 640)

        theme_path = os.path.normpath(os.path.join(
            os.path.dirname(__file__), '..', 'assets', 'theme.json'))
        if os.path.isfile(theme_path):
            try:
                with open(theme_path, encoding='utf-8') as f:
                    theme = json.load(f)
                self._load_theme(theme)
            except Exception:
                pass

        ctk.set_appearance_mode('Dark')

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self.main = MainWindow(self)
        self.main.grid(row=0, column=0, sticky='nsew')

    def _load_theme(self, theme):
        for widget, props in theme.items():
            cls = getattr(ctk, widget, None)
            if cls:
                for key, val in props.items():
                    try:
                        setattr(cls, key, val)
                    except Exception:
                        pass


def run():
    App().mainloop()

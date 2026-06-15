import os
import json
import customtkinter as ctk
from .ui.main_window import MainWindow


class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title('WebGuardian — Security Scanner')
        self.geometry('1200x820')
        self.minsize(960, 680)

        theme_path = os.path.join(os.path.dirname(__file__), '..', 'assets', 'theme.json')
        theme_path = os.path.normpath(os.path.abspath(theme_path))
        if os.path.isfile(theme_path):
            try:
                with open(theme_path) as f:
                    theme = json.load(f)
                ctk.set_default_color_theme('green')
                self._apply_theme(theme)
            except Exception:
                ctk.set_default_color_theme('green')
        else:
            ctk.set_default_color_theme('green')

        ctk.set_appearance_mode('dark')

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self.main_window = MainWindow(self)
        self.main_window.grid(row=0, column=0, sticky='nsew')

    def _apply_theme(self, theme):
        for widget, props in theme.items():
            if hasattr(ctk, widget):
                for prop, value in props.items():
                    try:
                        if isinstance(value, list):
                            setattr(getattr(ctk, widget), prop, value)
                        else:
                            setattr(getattr(ctk, widget), prop, value)
                    except Exception:
                        pass


def run():
    app = App()
    app.mainloop()

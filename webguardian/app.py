import customtkinter as ctk
from .ui.main_window import MainWindow


class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title('WebGuardian Security Scanner')
        self.geometry('1100x750')
        self.minsize(900, 600)
        ctk.set_appearance_mode('dark')
        ctk.set_default_color_theme('green')

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self.main_window = MainWindow(self)
        self.main_window.grid(row=0, column=0, sticky='nsew')


def run():
    app = App()
    app.mainloop()

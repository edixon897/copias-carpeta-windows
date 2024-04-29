import tkinter as tk

class App(tk.Frame):
    def __init__(self, master=None):
        super().__init__(master)
        self.pack()

# create the application
myapp = App()

#

#
myapp.master.title("My Do-Nothing Application")
myapp.master.maxsize(800, 400)


myapp.mainloop()
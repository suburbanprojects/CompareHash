from tkinter import *
from tkinter import ttk, filedialog
import hashlib

class MD5Gui:
    def __init__(self, app):
        self.root = app
        self.app_layout()
        
    def app_layout(self):

        self.EnterLabel = ttk.Label(app, text="File 1: ")
        self.EnterLabel.grid(column = 0, row = 0, ipadx=5, pady=5, sticky=W)
        self.ResultLabelA = ttk.Label(app, text="md5 hash: ")
        self.ResultLabelA.grid(column = 0, row = 1, ipadx=5, pady=5, sticky=W)

        self.EnterLabel = ttk.Label(app, text="File 2: ")
        self.EnterLabel.grid(column = 0, row = 2, ipadx=5, pady=5, sticky=W)
        self.ResultLabelB = ttk.Label(app, text="md5 hash: ")
        self.ResultLabelB.grid(column = 0, row = 3, ipadx=5, pady=5, sticky=W)

        self.ResultLabelC = ttk.Label(app, text="Hash Result: ")
        self.ResultLabelC.grid(column = 0, row = 4, ipadx=5, pady=5, sticky=W)

        self.EnterBox = ttk.Entry(app, width=75)
        self.EnterBox.grid(column=1,row=0,padx=10,pady=5, sticky=N)
        self.ResultBox = ttk.Entry(app, width=75)
        self.ResultBox.grid(column=1,row=1,padx=10,pady=5, sticky=N)

        self.EnterBox2 = ttk.Entry(app, width=75)
        self.EnterBox2.grid(column=1,row=2,padx=10,pady=5, sticky=N)
        self.ResultBox2 = ttk.Entry(app, width=75)
        self.ResultBox2.grid(column=1,row=3,padx=10,pady=5, sticky=N)

        self.HashResult = ttk.Entry(app, width=75)
        self.HashResult.grid(column=1,row=4,padx=10,pady=5, sticky=N)

        self.OpenFile = ttk.Button(app, text='Open File 1', command=self.openFile)
        self.OpenFile.grid(column=3, row=0)

        self.OpenFile = ttk.Button(app, text='Open File 2', command=self.openFile2)
        self.OpenFile.grid(column=3, row=2)

        self.CompareHash = ttk.Button(app, text='Compare Hash', command=self.compareHash)
        self.CompareHash.grid(column=0,row=5,padx=10,pady=5, sticky=N)

    def openFile(self):
        self.filename = filedialog.askopenfilename(initialdir="/",title="Dialog Box",
                                          filetypes=(("Text files", "*.txt"),
                                                     ("All files","*.*")))
        self.EnterBox.delete(0, "end")
        self.EnterBox.insert(0, self.filename)
        
        self.md5_hash = hashlib.md5()
        with open(self.filename, "rb") as f:
                  for byte_block in iter(lambda: f.read(4096),b''):
                      self.md5_hash.update(byte_block)
                  self.ResultBox.delete(0, "end") 
                  self.ResultBox.insert(0, self.md5_hash.hexdigest())

    def openFile2(self):
        self.filename = filedialog.askopenfilename(initialdir="/",title="Dialog Box",
                                          filetypes=(("Text files", "*.txt"),
                                                     ("All files","*.*")))
        self.EnterBox2.delete(0, "end")
        self.EnterBox2.insert(0, self.filename)

        self.md5_hash = hashlib.md5()
        with open(self.filename, "rb") as f:
                  for byte_block in iter(lambda: f.read(4096),b''):
                      self.md5_hash.update(byte_block)
                  self.ResultBox2.delete(0, "end") 
                  self.ResultBox2.insert(0, self.md5_hash.hexdigest())

    def compareHash(self):
        hash_a = self.ResultBox.get()
        hash_b = self.ResultBox2.get()

        if hash_a == hash_b:
            self.HashResult.delete(0, "end") 
            self.HashResult.insert(0, "Hashes Match")
        else:
            self.HashResult.delete(0, "end") 
            self.HashResult.insert(0, "Hashes Don't Match")

if __name__ == "__main__":
    app = Tk()
    app.title("MD5 File Hash")
    app.geometry("675x195")
    app.resizable(width=False, height=False)
    app2 = MD5Gui(app)
    app.mainloop()

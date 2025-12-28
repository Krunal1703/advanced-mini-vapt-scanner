import tkinter as tk
import subprocess

def run_scan():
    target = entry.get()
    subprocess.Popen(["python", "scanner.py", "--target", target])

root = tk.Tk()
root.title("Mini VAPT Scanner")

tk.Label(root, text="Target Domain / IP").pack()
entry = tk.Entry(root, width=30)
entry.pack()

tk.Button(root, text="Start Scan", command=run_scan).pack()

root.mainloop()

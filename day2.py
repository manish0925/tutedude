import tkinter as tk

window = tk.Tk()
window.title("My First GUI Program")
window.minsize(width=500, height=300)

label = tk.Label(text="My first GUI", font=("Times New Roman",24,"bold"))
label.pack()

label1 = tk.Label(text="Enter username")
label1.pack()
name = tk.Entry(width=30)
name.pack()

label2 = tk.Label(text="Enter Password")
label2.pack()
password = tk.Entry(width=30, show="*")
password.pack()

counter = 0

# Label to display click count
label3 = tk.Label(text="")
label3.pack()

def function():
    global counter
    counter += 1
    label3.config(text=f"Button clicked {counter} times")

button = tk.Button(text="Submit", command=function)
button.pack()

window.mainloop()

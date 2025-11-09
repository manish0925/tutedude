import tkinter as tk 
from tkinter import messagebox
from tkinter import ttk

window=tk.Tk()
window.title("User infromation form")
window.minsize(width=500, height=400)
lavel=tk.Label(text="User Information Form", font=("Arial",24,"bold"))
lavel.pack()


label1=tk.Label(text="Enter your Full Name")
label1.pack()
name=tk.Entry(width=30)
name.pack()

label2=tk.Label(text="Enter your Age")
label2.pack()
age=tk.Entry(width=30)
age.pack()

label3=tk.Label(text="Entre your pasword")
label3.pack()
password=tk.Entry(width=30, show="*")
password.pack()

def Submit():
    user_name=name.get()
    user_age=age.get()
    user_password=password.get()
    messagebox.showinfo(title="Information", message=f"Name: {user_name}\nAge: {user_age}\nPassword: {user_password}")
button=tk.Button(text="Submit", command=Submit)
button.pack()

window.mainloop()
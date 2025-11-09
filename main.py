import tkinter as tk        # Imports the tkinter library and gives it a shorter name 'tk'

window = tk.Tk()            # Creates the main application window

window.title("This is my first GUI Program")   # Sets the window title

window.minsize(width=500, height=300)          # Sets the minimum window size

label = tk.Label(text="Hello World!", font=("Arial", 24, "bold"))  # Creates a text label widget
label.pack()                 # Places the label on the window (center by default)
def function():
    label.grid  # Function to be called when the button is clicked
button=tk.Button(text="Submit",command=function)
button.pack()               # Places the button on the window
window.mainloop()            # Starts the GUI event loop (keeps the window open)

import tkinter as tk

def on_button_click(button_number):
    print(f"Button {button_number} clicked!")

# Create the main window
root = tk.Tk()
root.title("Button Example")

# Create buttons and add them to the window
button1 = tk.Button(root, text="Button 1", command=lambda: on_button_click(1))
button1.pack(pady=10)

button2 = tk.Button(root, text="Button 2", command=lambda: on_button_click(2))
button2.pack(pady=10)

button3 = tk.Button(root, text="Button 3", command=lambda: on_button_click(3))
button3.pack(pady=10)

# Run the application
root.mainloop()

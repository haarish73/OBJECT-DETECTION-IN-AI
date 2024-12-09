import tkinter as tk
import speech_recognition as sr

class Robot:
    def __init__(self):
        self.x = 0
        self.y = 0
        self.directions = ['N', 'E', 'S', 'W']
        self.current_direction_index = 0  # Start facing North

    def move_forward(self):
        if self.directions[self.current_direction_index] == 'N':
            self.y += 1
        elif self.directions[self.current_direction_index] == 'E':
            self.x += 1
        elif self.directions[self.current_direction_index] == 'S':
            self.y -= 1
        elif self.directions[self.current_direction_index] == 'W':
            self.x -= 1

    def turn_left(self):
        self.current_direction_index = (self.current_direction_index - 1) % 4

    def turn_right(self):
        self.current_direction_index = (self.current_direction_index + 1) % 4

    def get_position(self):
        return self.x, self.y

    def get_direction(self):
        return self.directions[self.current_direction_index]

class RobotGUI:
    def __init__(self, root, robot):
        self.robot = robot
        self.root = root
        self.root.title("Voice-Controlled Robot")

        self.position_label = tk.Label(root, text="Position: (0, 0)")
        self.position_label.pack()

        self.direction_label = tk.Label(root, text="Direction: N")
        self.direction_label.pack()

        self.listen_button = tk.Button(root, text="Listen for Command", command=self.listen_for_command)
        self.listen_button.pack()

    def move_forward(self):
        self.robot.move_forward()
        self.update_labels()

    def turn_left(self):
        self.robot.turn_left()
        self.update_labels()

    def turn_right(self):
        self.robot.turn_right()
        self.update_labels()

    def update_labels(self):
        position = self.robot.get_position()
        direction = self.robot.get_direction()
        self.position_label.config(text=f"Position: {position}")
        self.direction_label.config(text=f"Direction: {direction}")

    def listen_for_command(self):
        recognizer = sr.Recognizer()
        with sr.Microphone() as source:
            print("Listening for command...")
            audio = recognizer.listen(source)
        try:
            command = recognizer.recognize_google(audio).lower()
            print(f"Command received: {command}")
            if 'move' in command:
                self.move_forward()
            elif 'left' in command:
                self.turn_left()
            elif 'right' in command:
                self.turn_right()
            else:
                print("Unknown command.")
        except sr.UnknownValueError:
            print("Could not understand audio")
        except sr.RequestError as e:
            print(f"Could not request results; {e}")

# Create a robot instance
robot = Robot()

# Create the main window
root = tk.Tk()

# Create the GUI
robot_gui = RobotGUI(root, robot)

# Start the GUI event loop
root.mainloop()

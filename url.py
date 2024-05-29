import os
import shutil
import tkinter as tk
from tkinter import StringVar, ttk, messagebox, Toplevel, IntVar
import threading
import time
import getpass
import win32security
import win32con
import subprocess

# Obtener el nombre del usuario actual
current_user = getpass.getuser()
decision_global = None  # Decisión global para reemplazo de archivos

# Función para iniciar sesión con credenciales proporcionadas
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
        return True, handle  # Devolver el manejador para cierre posterior
    except win32security.error as e:
        return False, str(e)

# Función para revertir a la sesión original
def revert_to_self(handle):
    win32security.RevertToSelf()
    handle.Close()

# Función para solicitar credenciales
def request_credentials(ip):
    credentials = {'username': '', 'password': '', 'domain': ''}

    def try_login():
        usuario = user_entry.get()
        contraseña = password_entry.get()
        dominio = domain_entry.get()
        result, handle_or_error = logon_user(usuario, contraseña, dominio)
        if result:
            credentials['username'] = usuario
            credentials['password'] = contraseña
            credentials['domain'] = dominio
            messagebox.showinfo("Impersonation", "Impersonation exitosa.")
            cred_dialog.destroy()
            return handle_or_error  # Devolver el manejador del usuario autenticado
        else:
            messagebox.showerror("Impersonation fallida", handle_or_error)
            user_entry.delete(0, tk.END)
            password_entry.delete(0, tk.END)

    # Crear ventana para ingresar credenciales
    cred_dialog = Toplevel(root)
    cred_dialog.title("Credenciales de Windows para " + ip)
    ttk.Label(cred_dialog, text="Usuario:").grid(row=0, column=0, padx=10, pady=5)
    user_entry = ttk.Entry(cred_dialog)
    user_entry.grid(row=0, column=1, padx=10, pady=5)
    ttk.Label(cred_dialog, text="Contraseña:").grid(row=1, column=0, padx=10, pady=5)
    password_entry = ttk.Entry(cred_dialog, show="*")
    password_entry.grid(row=1, column=1, padx=10, pady=5)
    ttk.Label(cred_dialog, text="Dominio:").grid(row=2, column=0, padx=10, pady=5)
    domain_entry = ttk.Entry(cred_dialog)
    domain_entry.grid(row=2, column=1, padx=10, pady=5)
    ttk.Button(cred_dialog, text="Iniciar sesión", command=try_login).grid(row=3, column=0, columnspan=2, pady=10)

    cred_dialog.transient(root)
    cred_dialog.grab_set()
    cred_dialog.wait_window()

    return credentials

# Función para preguntar si se debe reemplazar un archivo existente
def ask_replace(file_name):
    global decision_global
    if decision_global is not None:
        return decision_global

    # Crear ventana de diálogo para la decisión
    dialog = Toplevel(root)
    dialog.title("Archivo existente")
    decision = IntVar(value=-1)  # -1 indeciso, 0 no, 1 sí
    apply_all = IntVar(value=0)  # 0 no aplicar a todos, 1 aplicar a todos

    ttk.Label(dialog, text=f"El archivo {os.path.basename(file_name)} ya existe. ¿Desea reemplazarlo?").grid(row=0, column=0, columnspan=2, padx=10, pady=10)
    ttk.Checkbutton(dialog, text="Aplicar a todos", variable=apply_all).grid(row=1, column=0, columnspan=2)
    ttk.Button(dialog, text="Sí reemplazar", command=lambda: [decision.set(1), dialog.destroy()]).grid(row=2, column=0, padx=5, pady=10)
    ttk.Button(dialog, text="No reemplazar", command=lambda: [decision.set(0), dialog.destroy()]).grid(row=2, column=1, padx=5, pady=10)

    dialog.transient(root)
    dialog.grab_set()
    dialog.wait_variable(decision)

    decision_value = decision.get()
    if apply_all.get() == 1:
        decision_global = decision_value

    return decision_value

# Función para verificar si se puede acceder a una IP mediante ping
def check_ip(ip):
    try:
        subprocess.check_output(["ping", "-n", "1", "-w", "2000", ip], stderr=subprocess.STDOUT)
        return True
    except subprocess.CalledProcessError:
        return False

# Función para copiar carpetas con manejo de permisos y autenticación
def copiar_carpeta(origenes, destinos, ip_origen, info_var, progreso_var, info_label, progreso_label, credentials):
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
                try:
                    os.makedirs(dst_dir, exist_ok=True)
                    shutil.copy2(src, dst)
                    archivos_copiados += 1
                except PermissionError:
                    messagebox.showwarning("Permisos insuficientes", f"No se puede acceder a {src}. Intentando con nuevas credenciales.")
                    credentials = request_credentials(ip_origen)
                    if credentials['username']:
                        result, handle = logon_user(credentials['username'], credentials['password'], credentials['domain'])
                        if result:
                            try:
                                shutil.copy2(src, dst)
                                archivos_copiados += 1
                                revert_to_self(handle)
                            except PermissionError as e:
                                messagebox.showerror("Error de Permisos", f"No se puede copiar {src}. Error: {str(e)}")
                                revert_to_self(handle)
                                continue
                        else:
                            messagebox.showerror("Error de Autenticación", "No se pudo autenticar con las nuevas credenciales.")
                            continue
                    else:
                        continue

                progress = archivos_copiados / total_archivos * 100
                progress_bar['value'] = progress
                progress_bar.update()
                elapsed_time = time.time() - start_time
                remaining_time = int((elapsed_time / archivos_copiados * total_archivos) - elapsed_time)
                info_var.set(f"Copiando de {src} a {dst}")
                progreso_var.set(f"IP {ip_origen} - Progreso: {int(progress)}% - Tiempo restante: {remaining_time} s")

    if archivos_copiados == 0:
        info_var.set(f"IP {ip_origen} No se copió ningún archivo")
        progreso_var.set("Proceso completado sin copiar archivos")
    else:
        info_var.set(f"IP {ip_origen} Copia completada exitosamente")
        progreso_var.set("Proceso completado al 100%")
    progreso_label.after(5000, progreso_label.destroy)
    decision_global = None

# Función manejadora para iniciar la copia y manejar autenticaciones
def copiar_carpeta_handler(ip_origen, ip_destino):
    if not check_ip(ip_origen):
        messagebox.showerror("Error", f"No se puede acceder a la IP de origen: {ip_origen}")
        return

    if not check_ip(ip_destino):
        messagebox.showerror("Error", f"No se puede acceder a la IP de destino: {ip_destino}")
        return

    # Configuración de direcciones IP, origenes y destinos
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
    info_var = StringVar(root, value="Esperando para iniciar la copia...")
    info_label = ttk.Label(root, textvariable=info_var)
    info_label.pack(pady=10)
    progreso_var = StringVar(root, value="Preparando copia...")
    progreso_label = ttk.Label(root, textvariable=progreso_var)
    progreso_label.pack(pady=5)

    # Función interna para ejecutar la copia en un hilo separado
    def execute_copy():
        credentials = {'username': '', 'password': '', 'domain': ''}
        for _ in range(2):  # Intentar dos veces si falla la autenticación
            try:
                copiar_carpeta(origenes, destinos, ip_origen, info_var, progreso_var, info_label, progreso_label, credentials)
                return
            except PermissionError:
                credentials = request_credentials(ip_origen)
                if credentials['username']:
                    handle = logon_user(credentials['username'], credentials['password'], credentials['domain'])
                    revert_to_self(handle)

    threading.Thread(target=execute_copy).start()

# Configuración de la interfaz gráfica
root = tk.Tk()
root.title("Herramienta de Copia de Seguridad de Windows")
root.geometry("600x400")

# Configuración del estilo de la interfaz
style = ttk.Style()
style.theme_use('clam')

style.configure("TLabel", font=("Arial", 12))
style.configure("TButton", font=("Arial", 12), padding=6)
style.configure("TEntry", padding=5)
style.configure("TProgressbar", thickness=20, troughcolor='#f2f2f2', background='#4caf50')

# Creación de los elementos de la interfaz
frame = ttk.Frame(root, padding="20")
frame.pack(fill=tk.BOTH, expand=True)

label_origen = ttk.Label(frame, text="IP de origen")
label_origen.grid(row=0, column=0, sticky=tk.W, pady=5, padx=5)
ip_origen_entry = ttk.Entry(frame, width=40)
ip_origen_entry.grid(row=0, column=1, pady=5, padx=5)
ip_origen_entry.insert(0, "192.168.0.128")

label_destino = ttk.Label(frame, text="IP de destino")
label_destino.grid(row=1, column=0, sticky=tk.W, pady=5, padx=5)
ip_destino_entry = ttk.Entry(frame, width=40)
ip_destino_entry.grid(row=1, column=1, pady=5, padx=5)
ip_destino_entry.insert(0, "192.168.0.114")

# Botón para iniciar la copia de seguridad
boton_copiar = ttk.Button(frame, text="Crear copia de seguridad", command=lambda: copiar_carpeta_handler(ip_origen_entry.get(), ip_destino_entry.get()))
boton_copiar.grid(row=2, column=0, columnspan=2, pady=20)

# Barra de progreso para mostrar el avance de la copia
progress_bar = ttk.Progressbar(frame, orient="horizontal", length=400, mode="determinate")
progress_bar.grid(row=3, column=0, columnspan=2, pady=10)

root.mainloop()

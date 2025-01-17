
import os
import shutil
import tkinter as tk
from tkinter import messagebox, Label, Button, Entry, StringVar, Toplevel, Checkbutton, IntVar
import threading
import time
import win32netcon
import win32net


decision_global = None  # Almacena la decisión global si se aplica a todos
def connect_network_drive(ip, user, password):
    """Intenta conectar un recurso de red con las credenciales dadas."""
    try:
        # Define la ruta UNC a la carpeta compartida
        network_path = f"\\\\{ip}\\"
        win32net.NetUseAdd(None, 2, {
            'remote': network_path,
            'local': '',
            'password': password,
            'username': user
        }, win32netcon.USE_FORCE)
        return True
    except Exception as e:
        if '1326' in str(e):
            # Error 1326 es incorrect user ID or password
            return 'bad password'
        elif '53' in str(e):
            # Error 53 is network path not found
            return 'bad user'
        return 'error'

def request_credentials(ip):
    """Solicita credenciales al usuario y maneja la conexión."""
    cred_dialog = Toplevel(root)
    cred_dialog.title("Credenciales de Red")
    Label(cred_dialog, text=f"Ingrese credenciales para {ip}").grid(row=0, column=0, columnspan=2)
    
    Label(cred_dialog, text="Usuario:").grid(row=1, column=0)
    user_entry = Entry(cred_dialog)
    user_entry.grid(row=1, column=1)
    
    Label(cred_dialog, text="Contraseña:").grid(row=2, column=0)
    password_entry = Entry(cred_dialog, show="*")
    password_entry.grid(row=2, column=1)
    
    def try_login():
        user = user_entry.get()
        password = password_entry.get()
        result = connect_network_drive(ip, user, password)
        if result == True:
            messagebox.showinfo("Conexión", "Conexión exitosa.")
            cred_dialog.destroy()
        elif result == 'bad password':
            messagebox.showerror("Error", "Contraseña incorrecta, intente nuevamente.")
        elif result == 'bad user':
            messagebox.showerror("Error", "Usuario incorrecto o ruta no accesible.")
        else:
            messagebox.showerror("Error", "Error al conectar con la red.")
    
    Button(cred_dialog, text="Login", command=try_login).grid(row=3, column=0, columnspan=2)
    cred_dialog.transient(root)
    cred_dialog.grab_set()
    cred_dialog.wait_window()





def ask_replace(file_name):
    global decision_global
    if decision_global is not None:    
        return decision_global

    dialog = Toplevel(root)
    dialog.title("Archivo existente")
    decision = IntVar(value=-1)  # -1 no decidido, 0 no, 1 sí
    apply_all = IntVar(value=0)  # 0 no aplicar a todos, 1 aplicar a todos

    Label(dialog, text=f"El archivo {os.path.basename(file_name)} ya existe. ¿Desea reemplazarlo?").grid(row=0, column=0, columnspan=2, padx=10, pady=10)
    Checkbutton(dialog, text="Aplicar a todos", variable=apply_all).grid(row=1, column=0, columnspan=2)
    Button(dialog, text="Sí remplazar", command=lambda: [decision.set(1), dialog.destroy()]).grid(row=2, column=0, padx=5, pady=10)
    Button(dialog, text="No remplazar", command=lambda: [decision.set(0), dialog.destroy()]).grid(row=2, column=1, padx=5, pady=10)

    dialog.transient(root)  
    dialog.grab_set()  
    dialog.wait_variable(decision)
    decision.get(), apply_all.get()
    if apply_all.get() == 1:
        decision_global = decision.get()
    return decision.get()

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
                progreso = archivos_copiados / total_archivos * 100
                elapsed_time = time.time() - start_time
                remaining_time = int((elapsed_time / archivos_copiados * total_archivos) - elapsed_time)
                info_var.set(f"Copiando de {src} a {dst}")
                progreso_var.set(f"IP {ip_origen} - Progreso: {int(progreso)}% - Tiempo restante: {remaining_time} s")

    info_var.set(f"IP {ip_origen} Copia completada exitosamente")
    progreso_var.set("Proceso completado al 100%")
    progreso_label.after(5000, progreso_label.destroy)
    decision_global = None  

    


def copiar_carpeta_handler(ip_origen, ip_destino):
    # Configuración inicial de origenes y destinos basada en IPs
    # Puede agregar más configuraciones de IP aquí según sea necesario
    if not os.path.exists(f"//{ip_origen}//compartidos"):
        request_credentials(ip_origen)
    config_ip = {
        '192.168.0.128': {
            'destinos': ['C:\\probando copias', 'C:\\probando copia'],
            'origenes': ['//192.168.0.128\\compartidos', '//192.168.0.128\\Costos\\Costos 2023']
        },
        '192.168.0.15': {
            'destinos': ['C:\\probando copias'],
            'origenes': ['//192.168.0.15\\Empresa']
        }
    }

    if ip_origen not in config_ip or ip_destino != '192.168.0.114':
        messagebox.showerror("Error", "Dirección IP no configurada, revisar.")
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
root.geometry("600x400")

label = tk.Label(root, text="IP de origen", font=("Arial", 10))
label.pack(pady=1)
ip_origen_entry = Entry(root, width=30)
ip_origen_entry.pack(pady=10)
ip_origen_entry.insert(0, "192.168.0.128")

label = tk.Label(root, text="IP de destino", font=("Arial", 10))
label.pack(pady=1)
ip_destino_entry = Entry(root, width=30)
ip_destino_entry.pack(pady=1)
ip_destino_entry.insert(0, "192.168.0.114")

boton_copiar = Button(root, text="Crear copia de seguridad",  font=("Arial", 10), command=lambda: copiar_carpeta_handler(ip_origen_entry.get(), ip_destino_entry.get()))
boton_copiar.pack(pady=20)

root.mainloop()

contenido = """Café,10,150.00
Té,5,45.00
Galletas,20,60.00
Jugo,30,90.00
Pan,15,30.00
"""

# Creando y escribiendo en el archivo
with open('data.txt', 'w') as file:
    file.write(contenido)
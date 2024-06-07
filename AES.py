from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
import base64

def generar_clave(tamano: int):
    key = os.urandom(tamano)
    return key

def guardar_clave(key: bytes, nombre_archivo: str):
    archivo = nombre_archivo + ".txt"
    with open(archivo, "w") as f:
        f.write(base64.b64encode(key).decode())
    print(f"Clave guardada en '{archivo}'")

def leer_clave(nombre_archivo: str):
    archivo = nombre_archivo + ".txt"
    with open(archivo, "r") as f:
        key = base64.b64decode(f.readline().strip())
    return key

def cifrar_texto(texto: bytes, key: bytes, nombre_archivo_salida: str):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(texto) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    archivo_salida = nombre_archivo_salida + ".txt"
    # Guardar IV y texto cifrado en base64
    with open(archivo_salida, "w") as f:
        f.write(base64.b64encode(iv).decode() + "\n")
        f.write(base64.b64encode(ciphertext).decode())
    print(f"Texto cifrado guardado en '{archivo_salida}'")

def descifrar_texto(nombre_archivo_entrada: str, key: bytes):
    archivo_entrada = nombre_archivo_entrada + ".txt"
    with open(archivo_entrada, "r") as f:
        iv = base64.b64decode(f.readline().strip())
        ciphertext = base64.b64decode(f.read().strip())
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    plaintext = unpadder.update(decrypted_padded_data) + unpadder.finalize()
    
    archivo_salida =  "Descifrado.txt"
    # Guardar IV y texto cifrado en base64
    with open(archivo_salida, "w") as f:
        f.write(plaintext.decode())
    print(f"Texto descifrado guardado en '{archivo_salida}'")
    return plaintext

def menu():
    while True:
        print("\nMenu:")
        print("1. Generar llave y guardar en archivo")
        print("2. Cifrar texto usando archivo de llave")
        print("3. Descifrar texto usando archivo de llave")
        print("4. Salir")
        opcion = input("Selecciona una opción: ")

        if opcion == '1':
            tamano = int(input("Introduce el tamaño en bytes de la clave (16, 24, 32): "))
            nombre_archivo_llave = input("Introduce el nombre del archivo para guardar la llave (sin extensión): ")
            key = generar_clave(tamano)
            guardar_clave(key, nombre_archivo_llave)
        
        elif opcion == '2':
            nombre_archivo_llave = input("Introduce el nombre del archivo de la llave (sin extensión): ")
            archivo_texto = input("Introduce el nombre del archivo de texto a cifrar: ")
            nombre_archivo_cifrado = input("Introduce el nombre del archivo de salida para el texto cifrado (sin extensión): ")
            key = leer_clave(nombre_archivo_llave)
            with open(archivo_texto, "rb") as f:
                texto_a_cifrar = f.read()
            cifrar_texto(texto_a_cifrar, key, nombre_archivo_cifrado)
        
        elif opcion == '3':
            nombre_archivo_llave = input("Introduce el nombre del archivo de la llave (sin extensión): ")
            nombre_archivo_cifrado = input("Introduce el nombre del archivo de texto cifrado (sin extensión): ")
            key = leer_clave(nombre_archivo_llave)
            texto_descifrado = descifrar_texto(nombre_archivo_cifrado, key)
            print(f"Texto descifrado: {texto_descifrado.decode()}")
        
        elif opcion == '4':
            break
        
        else:
            print("Opción no válida. Por favor, selecciona una opción válida.")

if __name__ == "__main__":
    menu()
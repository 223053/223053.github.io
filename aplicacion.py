from flask import Flask, render_template, request
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

app = Flask(__name__)

# Función para cifrar
def cifrar(texto, clave, iv):
    cipher = AES.new(clave, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(texto.encode('utf-8'))
    return ciphertext, tag

# Función para descifrar
def descifrar(ciphertext, tag, clave, iv):
    cipher = AES.new(clave, AES.MODE_GCM, nonce=iv)
    texto = cipher.decrypt_and_verify(ciphertext, tag)
    return texto.decode('utf-8')

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        mensaje = request.form["mensaje"]  # Obtiene el mensaje del formulario
        clave = get_random_bytes(32)  # Clave aleatoria de 256 bits
        iv = get_random_bytes(12)  # IV aleatorio de 12 bytes para GCM

        # Cifrado
        ciphertext, tag = cifrar(mensaje, clave, iv)

        # Descifrado
        decrypted_message = descifrar(ciphertext, tag, clave, iv)

        return render_template("index.html", mensaje=mensaje, ciphertext=ciphertext.hex(), decrypted_message=decrypted_message)
    
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)

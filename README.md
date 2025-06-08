# Generación de Llaves JWT con OpenSSL

Este proyecto utiliza autenticación basada en JWT con firma RSA. Para que funcione correctamente, debes generar un par de llaves: una privada para firmar los tokens y una pública para verificarlos.

---

## ✅ Requisitos

- Tener instalado `OpenSSL` en tu máquina.
    - En Linux/macOS ya suele venir preinstalado.
    - En Windows puedes instalarlo desde [https://slproweb.com/products/Win32OpenSSL.html](https://slproweb.com/products/Win32OpenSSL.html) o usar Git Bash/WSL.

---

## 📁 Estructura esperada

Crea el siguiente directorio dentro del módulo `resources`:


---

## 🔐 Comandos para generar las llaves

1. Abre tu terminal en la ruta del proyecto.
2. Ejecuta los siguientes comandos desde la carpeta `src/main/resources/jwtKeys`:

```bash
openssl genrsa -out private_key.pem 2048

openssl rsa -pubout -in private_key.pem -out public_key.pem

src/main/resources/jwtKeys/
├── private_key.pem
└── public_key.pem
```
# Ignorar claves JWT
src/main/resources/jwtKeys/*.pem




Grupo 9 — Demo: Prevención básica de inyección y seguridad de autenticación
Proyecto de apoyo para la Etapa 3 del TP de Ingeniería de Software. Contiene una pequeña aplicación de escritorio en Python (Tkinter + SQLite) que compara una implementación vulnerable de login con una implementada de forma segura.
El objetivo es demostrar medidas básicas de seguridad en el código: consultas parametrizadas (evitan SQLi), hashing de contraseñas con PBKDF2-HMAC+salt, bloqueo temporal por intentos fallidos, validación de inputs y logging estructurado de eventos de seguridad.
Entrega lista para ejecutar con python setup_db.py y python app.py (sin dependencias externas).

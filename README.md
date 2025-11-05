Grupo 7 — Demo de Seguridad y Prevención de Inyección

Proyecto correspondiente a la Etapa 3 del Trabajo Práctico de Ingeniería de Software. Consiste en una aplicación de escritorio desarrollada en Python utilizando Tkinter y SQLite, cuyo propósito es demostrar técnicas básicas de protección frente a inyección de código y ataques de autenticación. La aplicación implementa un sistema de login reforzado con hashing PBKDF2-HMAC y salt aleatorio, consultas SQL parametrizadas, bloqueo temporal de cuentas tras múltiples intentos fallidos, validación de entradas y auditoría estructurada de eventos en formato JSON.

El entorno se ejecuta sin dependencias externas. La base de datos se inicializa con setup_db.py, que crea los usuarios semilla del Grupo 7, y puede actualizarse posteriormente con migrate_db.py en caso de agregar columnas como login_count o last_login. La interfaz gráfica se inicia con app.py, donde se centraliza la lógica de autenticación y los paneles de usuario y administrador. Todos los eventos se registran en data/security.log, garantizando trazabilidad y evidencia de acciones.

El objetivo no es la complejidad técnica sino la demostración consciente de buenas prácticas de seguridad: separación de responsabilidades, almacenamiento seguro de credenciales, detección de inyecciones, bloqueo progresivo ante intentos reiterados y registro auditable de los incidentes. De esta manera se evidencia cómo aplicar principios de hardening y control de acceso en el contexto de una organización como el Banco Santander, priorizando la integridad y la verificación de cada operación.

El repositorio con el código fuente, scripts de inicialización y logs de auditoría está disponible en GitHub:
https://github.com/tu_usuario/Grupo7_IS
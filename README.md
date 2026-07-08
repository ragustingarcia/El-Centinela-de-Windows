# 🛡️ El Centinela de Windows

**Limpiador y optimizador de Windows para cualquiera.** Diagnostica antes de tocar nada, siempre pregunta antes de actuar, y nunca borra lo que no reconoce.

Arranque, seguridad, privacidad, programas innecesarios, espacio en disco y apps de la Tienda preinstaladas — todo desde un menú, sin instalar nada.

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![Platform: Windows](https://img.shields.io/badge/platform-Windows%2010%2F11-0078D6?logo=windows&logoColor=white)](#)

---

## Instalación

No hace falta instalar nada. Descargá `El Centinela de Windows.bat` y hacé doble clic.

Va a pedir permisos de administrador (los necesita para tocar el registro, servicios y Windows Defender) — aceptá el cartel de Windows. Es re-ejecutable: lo que ya está resuelto se detecta solo y se saltea.

---

## Funcionalidades

### 🔎 Reporte completo
Corre las 6 categorías en modo solo-lectura. No modifica absolutamente nada — la forma segura de ver el estado real de la PC antes de decidir qué tocar.

### 🚀 Arranque y persistencia
Registro Run/RunOnce, carpetas de Startup, tareas programadas, servicios de terceros y los puntos de secuestro clásicos de Windows (Winlogon, AppInit_DLLs, LSA, IFEO, suscripciones WMI). Cada hallazgo se verifica contra su firma digital. Detecta apps que reescriben su propio arranque (Discord, Docker Desktop, Steam, etc.) y te dice en qué menú de la app apagarlo de raíz, en vez de un parche que vuelve.

### 🛡️ Seguridad (Windows Defender)
Estado de protección en tiempo real, último scan, exclusiones (limpia automáticamente las que apuntan a archivos que ya no existen), y te deja disparar un scan rápido o completo.

### 🔕 Privacidad
Apaga las 10 sugerencias/publicidad de Windows (recomendaciones del menú Inicio, apps instaladas en silencio, apps OEM, pantalla de bloqueo) — con las políticas de grupo que realmente persisten, no solo el toggle blando que Windows puede resincronizar solo.

### 🧹 Programas conocidos como innecesarios
Lista curada con dos niveles de confianza: verificado en una máquina real, o documentado por la comunidad pero no probado todavía. Nunca desinstala nada sin confirmación explícita.

### 💾 Limpieza de disco
Temporales de usuario y sistema, cache de Chrome/Edge, Papelera de reciclaje, descargas viejas de Windows Update, cache de Delivery Optimization. Muestra el tamaño de cada cosa antes de preguntar, y cuánto espacio liberaste al final.

### 🏪 Apps de la Tienda preinstaladas
Candy Crush, Disney+, TikTok, redes sociales y demás — con **lista blanca estricta**: solo se ofrece sacar lo explícitamente permitido, nunca nada por fuera de esa lista (muchos paquetes de la Tienda son piezas internas de Windows y sacar el equivocado puede romper el sistema).

---

## Filosofía de seguridad

- **Diagnóstico primero.** Todo hallazgo se muestra con contexto (firma digital, editor, ruta) antes de preguntar nada.
- **Nunca actúa sin confirmación**, ítem por ítem, ni siquiera en la categoría de bloatware conocido.
- **Lista blanca, no lista negra**, para todo lo que implica desinstalar software del sistema — se ofrece sacar lo explícitamente permitido, nunca "todo menos lo protegido".
- **Re-ejecutable**, sin efectos secundarios por correrlo más de una vez.

---

## Arquitectura

Un solo archivo `.bat` con estructura híbrida: la parte batch solo pide permisos de administrador, y después se copia a un `.ps1` temporal que corre en PowerShell 7 (`pwsh`) — que sí puede mostrar progreso y manejar registro, WMI y Windows Defender correctamente.

---

## Licencia

[MIT](./LICENSE)

---

## Autor

**Rodolfo Agustín García** ([@ragustingarcia](https://github.com/ragustingarcia)) — [ragustingarcia.com](https://ragustingarcia.com/)

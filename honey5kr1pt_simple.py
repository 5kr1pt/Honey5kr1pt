#!/usr/bin/env python
"""
Honey5kr1pt – honeypot simplificado (1 arquivo)

Fluxo
=====
1. Pergunta IP / share / subpasta / nome e tamanho da isca
2. Cria arquivo-isca e aplica SACL (auditoria GENERIC_READ)
3. Faz tail do Security Event Log:
     • 4624  → guarda (LogonID → IP) no cache
     • 4663/4656 → se objeto == isca → emite log com usuário + IP
4. Grava em console e no arquivo honey5kr1pt.log
"""

import os
import sys
import time
import logging
import re
from datetime import datetime, timedelta
from pathlib import Path
from datetime import datetime, timedelta
from colorama import Fore, Style, init
import pywintypes  


# --------- dependências pywin32 -------------
import win32con
import win32evtlog
import win32security
# --------------------------------------------

init(autoreset=True)

ASCII_ART = f"""{Fore.YELLOW}

                                               █████            
                                        ██    █▓░░░██████       
                                    ████ ██  ██░░░░██░░░░█      
                                      █████  █░░░██░░░░░░█      
                                     ████▓████░░██░░░░░░██      
                                    ██░░░░░░░████░░░░░██        
                                    █░░░░█░░░████░████          
            ███▓░░░░░░░░░░░░░░░░░▒████░██▒░░░███░░██░██         
          ██░▓▓███████████████████▓▒▒██░░░░████░░░██░░█         
          █░░░░▓██████████████████▒░░░███████▒░░░██▓░▒██        
          ██░░░░░░░░░░░░░░░░░░░░░░░░░██     ██░███░░████        
           █░▓██░░░░░▓░░░░██████████░██        █████  █         
         ███░█░█░░░█████▓██░░░░░░░▓█░░██              ██        
        ██░▒██░█░░░█░░░░█▓░░░░░░░░░▒▓▒░░██            ██        
       ██░░░░░░█░░▓█░░░░░░░░░▒▒▒░░░░░░█░░█           ███        
      ██░░░▒░░░░███░░░▒▒▒░▒░▒░░░▒▒▒░░░░▓░▓█       █████         
      █▓░░▒▒░█▓░░█░░░░░░░░░░░░░░░░░░░░░░░░█     █ ██            
      █░░▒▒▒░██▓██░███▒▒███░░███▒█░██░▒░▓░██   ██               
      █░░░▒▒░██░▒█░█░░█░█░████░█░███░░░░▓░██  ██                
      █▓░░▒▒░█░░░█░▓██░░█░█░░███░░█░░░░░▒░█   ██                
      ██░░▒▒░░███░█░░░░░░░░██░░░░█░░█░░▒░▒█     ██              
       █░░░▒░▓█▒░░█▒██░███▓▒█░████░██▓░░░██                     
        █░░░░░░░█▒███░░█░░░░█░█░░█▒██░░░██                      
         █░░░░██▓░█░░█░█░░░░█░███▒░░░░░██                       
          █▓░░░░░░░░░░░░░░░░░░█░░░░░░░██                        
           ██░░░░░░▒░░▒▒▒▒░▒░░░░░░░░▓██                         
            ████▒░░░░░░░░░░░░░░▒███░██                          
            █░░░░███████████████░░░░██                          
              ████▒░░░░░░░░░░░░▓████                            
                    ██████████  

                         Honey5kr1pt
                  by Paulo “5kr1pt” Werneck

{Style.RESET_ALL}"""

SLEEP_TIME = 1
TIMEOUT = SLEEP_TIME + 1

# ------------ logging -----------------------
log = logging.getLogger("honey5kr1pt")
log.setLevel(logging.INFO)
for h in (
    logging.StreamHandler(sys.stdout),
    logging.FileHandler("honey5kr1pt.log", encoding="utf-8"),
):
    h.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
    log.addHandler(h)
# --------------------------------------------

# ------------ util interact -----------------
def ask(prompt: str, default: str = "") -> str:
    resp = input(f"{prompt} [{default}]: ").strip()
    return resp or default


def get_parameters():
    server = ask("IP ou hostname do File Server", "ex: 192.168.0.1")
    share  = ask("Nome do compartilhamento", "ex: dados$")
    sub    = ask("Subpasta onde ficará a isca (vazio = raiz)", "")
    fname  = ask("Nome do arquivo isca", "isca.xlsx")
    sizek  = int(ask("Tamanho em KB (0 = vazio)", "0"))
    unc    = f"\\\\{server}\\{share}"
    bait   = (Path(unc) / sub / fname) if sub else (Path(unc) / fname)
    return unc, bait, sizek


# ----------- criação de isca/SACL -----------
EVERYONE = win32security.CreateWellKnownSid(win32security.WinWorldSid, None)


def create_bait_file(path: Path, size_kb: int):
    path.parent.mkdir(parents=True, exist_ok=True)
    data = b"\x00" * (size_kb * 1024) if size_kb else b""
    path.write_bytes(data)
    log.info("Isca criada: %s (%d KB)", path, size_kb)


def add_audit(path: Path) -> bool:
    """
    Aplica a SACL de auditoria.
    Retorna True se OK; False se faltar privilégio (erro 1314).
    """
    try:
        sd = win32security.GetFileSecurity(
            str(path), win32security.DACL_SECURITY_INFORMATION
        )
        sacl = win32security.ACL()
        sacl.AddAuditAccessAceEx(
            win32con.ACL_REVISION,
            win32con.SUCCESSFUL_ACCESS_ACE_FLAG | win32con.FAILED_ACCESS_ACE_FLAG,
            win32con.GENERIC_READ,
            EVERYONE,
            True,
            True,
        )
        sd.SetSecurityDescriptorSacl(1, sacl, 0)
        win32security.SetFileSecurity(
            str(path), win32security.SACL_SECURITY_INFORMATION, sd
        )
        log.info("SACL aplicada para auditar leitura (GENERIC_READ).")
        return True

    except pywintypes.error as e:
        # ---- Falta de privilégio (SetFileSecurity erro 1314) ----
        if e.winerror == 1314:
            msg_plain = (
                "Permissão negada ao definir auditoria (erro 1314).\n"
                "Execute este script como:\n"
                "  • Administrador **local** do servidor, ou\n"
                "  • Conta com privilégio SeSecurityPrivilege "
                "(ex.: Administradores de Domínio)."
            )
            msg_color = f"{Fore.RED}{msg_plain}{Style.RESET_ALL}"

            for h in log.handlers:
                is_console = isinstance(h, logging.StreamHandler)
                h.emit(
                    logging.LogRecord(
                        name=log.name,
                        level=logging.ERROR,
                        pathname=__file__,
                        lineno=0,
                        msg=msg_color if is_console else msg_plain,
                        args=(),
                        exc_info=None,
                    )
                )
            return False
        # ---- Outros erros: deixa propagar ----
        raise 


# ------------- monitor de eventos -----------
EVENT_IDS_ACCESS = {4663, 4656}
EVENT_ID_LOGON   = 4624
RE_IP            = re.compile(r"IpAddress:\s+([\d\.]+)", re.I)
CACHE_TTL_MIN    = 30  # tempo de vida do IP em cache


def _prune(cache: dict[str, tuple[str, datetime]]):
    limite = datetime.now() - timedelta(minutes=CACHE_TTL_MIN)
    for key in [k for k, (_, ts) in cache.items() if ts < limite]:
        cache.pop(key, None)


def tail_security_log(bait: Path):
    # ------------------------------------------------------------------
    # 1) MARCO TEMPORAL – tudo que aconteceu ANTES deste momento
    #    (criação do arquivo + aplicação de SACL) será ignorado.
    # ------------------------------------------------------------------
    start_ts = datetime.now()

    handle = win32evtlog.OpenEventLog(None, "Security")
    flags  = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    record = (
        win32evtlog.GetOldestEventLogRecord(handle)
        + win32evtlog.GetNumberOfEventLogRecords(handle)
    )

    ip_cache: dict[str, tuple[str, datetime]] = {}  # LogonID → (ip, timestamp)

    log.info("Iniciando monitoramento de eventos… Ctrl+C para sair.")

    while True:
        events = win32evtlog.ReadEventLog(handle, flags, record)
        if not events:
            time.sleep(1)
            continue

        for ev in events:
            record = ev.RecordNumber + 1

            # ----------------------------------------------------------
            # 2) DESCARTA eventos ocorridos antes do script iniciar
            # ----------------------------------------------------------
            if ev.TimeGenerated < start_ts:
                continue

            inserts = ev.StringInserts or []
            blob    = "\n".join(inserts)

            # -------- 4624 → cache de IP -----------------------------
            if ev.EventID == EVENT_ID_LOGON:
                if len(inserts) >= 19:
                    logon_id = inserts[8]          # New Logon ID
                    ip_addr  = inserts[18]         # Network Address
                    if ip_addr and ip_addr != "-":
                        ip_cache[logon_id] = (ip_addr, datetime.now())
                        _prune(ip_cache)
                continue

            # -------- 4663 / 4656 → acesso ao arquivo ----------------
            if ev.EventID not in EVENT_IDS_ACCESS:
                continue
            if bait.name.lower() not in blob.lower() and str(bait).lower() not in blob.lower():
                continue

            user_name = inserts[1] if len(inserts) > 1 else "?"
            logon_id  = inserts[4] if len(inserts) > 4 else None
            ip_addr   = ip_cache.get(logon_id, ("–",))[0] if logon_id else "–"

            
            if user_name.endswith("$"):
                continue

            log.info(
                "ACESSO id=%s user=%s ip=%s time=%s",
                ev.EventID,
                user_name,
                ip_addr,
                ev.TimeGenerated,
            )


# -------------------- main -------------------
def main():
    print(ASCII_ART)
    
    unc, bait_path, size_kb = get_parameters()

    if not Path(unc).exists():
        log.error("UNC não alcançável: %s", unc)
        sys.exit(1)

    create_bait_file(bait_path, size_kb)

    if not add_audit(bait_path):
        sys.exit(1)          # encerra se falhou por privilégio

    # segue normalmente
    tail_security_log(bait_path)

    try:
        tail_security_log(bait_path)
    except KeyboardInterrupt:
        log.info("Encerrado pelo usuário.")


if __name__ == "__main__":
    if os.name != "nt":
        print("Este script só funciona em Windows (pywin32).")
        sys.exit(1)
    main()
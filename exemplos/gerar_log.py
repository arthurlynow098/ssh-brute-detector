"""Gera um auth.log de laboratório com três cenários.

Os IPs são das faixas reservadas para documentação (RFC 5737),
então não apontam para ninguém de verdade.
"""
from datetime import datetime, timedelta
from pathlib import Path

base = datetime(2026, 11, 14, 3, 12, 0)
pid = 4100
lines = []


def log(dt, msg):
    global pid
    pid += 1
    lines.append(f"{dt:%b %d %H:%M:%S} srv-lab sshd[{pid}]: {msg}")


# rotina normal, o admin entrando de manhã
log(base.replace(hour=8, minute=1), "Accepted publickey for arthur from 192.0.2.10 port 51122 ssh2")

# cenário 1, força bruta clássica no root
for i in range(12):
    log(base + timedelta(seconds=20 * i), "Failed password for root from 203.0.113.45 port 40122 ssh2")

# cenário 2, spraying com usuários comuns, devagar
for i, user in enumerate(["admin", "ubuntu", "oracle", "postgres", "test", "git"]):
    log(base + timedelta(minutes=30 + 4 * i), f"Invalid user {user} from 198.51.100.77 port 3321{i}")

# cenário 3, várias falhas e depois um login que funcionou
for i in range(7):
    log(base + timedelta(hours=2, seconds=15 * i), "Failed password for deploy from 203.0.113.99 port 55012 ssh2")
log(base + timedelta(hours=2, minutes=3), "Accepted password for deploy from 203.0.113.99 port 55013 ssh2")

# ruído que o parser precisa ignorar
lines.append(f"{base:%b %d %H:%M:%S} srv-lab CRON[999]: pam_unix(cron:session): session opened for user root")

lines.sort(key=lambda l: datetime.strptime("2026 " + l[:15], "%Y %b %d %H:%M:%S"))
Path(__file__).with_name("auth.log").write_text("\n".join(lines) + "\n", encoding="utf-8")
print(f"{len(lines)} linhas escritas")

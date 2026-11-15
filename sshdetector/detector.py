"""Regras de detecção.

Regra 1, força bruta. Um IP com N falhas dentro de uma janela de tempo.
Uso janela deslizante porque contar o total do dia esconde rajadas curtas.

Regra 2, password spraying. Um IP tentando muitos usuários diferentes,
poucas vezes cada um, para não travar contas.

Regra 3, possível acesso indevido. Um login com sucesso vindo de um IP
que antes tinha falhado muitas vezes. Esse é o alerta mais grave.
"""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import timedelta

from .parser import Event

MITRE = {
    "forca_bruta": "T1110.001 Password Guessing",
    "spraying": "T1110.003 Password Spraying",
    "acesso_suspeito": "T1078 Valid Accounts",
}


@dataclass
class Alert:
    rule: str
    severity: str
    ip: str
    detail: str
    first_seen: str
    mitre: str = field(init=False)

    def __post_init__(self):
        self.mitre = MITRE[self.rule]


def detect(events: list[Event], threshold: int = 5, window_min: int = 10,
           spray_users: int = 4) -> list[Alert]:
    events = sorted(events, key=lambda e: e.when)
    window = timedelta(minutes=window_min)
    recent: dict[str, deque] = defaultdict(deque)
    failures: dict[str, int] = defaultdict(int)
    users_tried: dict[str, set] = defaultdict(set)
    first: dict[str, str] = {}
    alerts: list[Alert] = []
    flagged: set[tuple[str, str]] = set()

    for ev in events:
        first.setdefault(ev.ip, ev.when.isoformat(sep=" "))
        if ev.kind in ("falha", "invalido"):
            failures[ev.ip] += 1
            users_tried[ev.ip].add(ev.user)
            q = recent[ev.ip]
            q.append(ev.when)
            while q and ev.when - q[0] > window:
                q.popleft()
            if len(q) >= threshold and ("forca_bruta", ev.ip) not in flagged:
                flagged.add(("forca_bruta", ev.ip))
                alerts.append(Alert("forca_bruta", "alta", ev.ip,
                                    f"{len(q)} falhas em menos de {window_min} min", first[ev.ip]))
            if len(users_tried[ev.ip]) >= spray_users and ("spraying", ev.ip) not in flagged:
                flagged.add(("spraying", ev.ip))
                alerts.append(Alert("spraying", "media", ev.ip,
                                    f"tentou {len(users_tried[ev.ip])} usuários diferentes", first[ev.ip]))
        elif ev.kind == "sucesso" and failures[ev.ip] >= threshold:
            alerts.append(Alert("acesso_suspeito", "critica", ev.ip,
                                f"login de {ev.user} aceito depois de {failures[ev.ip]} falhas",
                                first[ev.ip]))
    return alerts


def summary(events: list[Event]) -> dict:
    by_ip: dict[str, int] = defaultdict(int)
    by_user: dict[str, int] = defaultdict(int)
    for ev in events:
        if ev.kind != "sucesso":
            by_ip[ev.ip] += 1
            by_user[ev.user] += 1
    top = lambda d: sorted(d.items(), key=lambda kv: kv[1], reverse=True)[:5]  # noqa: E731
    return {
        "eventos": len(events),
        "falhas": sum(e.kind != "sucesso" for e in events),
        "sucessos": sum(e.kind == "sucesso" for e in events),
        "top_ips": top(by_ip),
        "top_usuarios": top(by_user),
    }

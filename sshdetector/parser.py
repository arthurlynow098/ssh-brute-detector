"""Leitura das linhas do auth.log gerado pelo sshd.

As linhas do syslog não têm ano, então o ano entra como parâmetro.
Só me importam três tipos de evento, falha, sucesso e usuário inválido.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime

LINE = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[\d+\]: (?P<msg>.*)$"
)
FAILED = re.compile(r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)")
ACCEPTED = re.compile(r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\d.]+)")
INVALID = re.compile(r"Invalid user (?P<user>\S*) from (?P<ip>[\d.]+)")


@dataclass(frozen=True)
class Event:
    when: datetime
    kind: str  # falha, sucesso ou invalido
    user: str
    ip: str


def parse_line(line: str, year: int) -> Event | None:
    m = LINE.match(line.strip())
    if not m:
        return None
    when = datetime.strptime(f"{year} {' '.join(m['ts'].split())}", "%Y %b %d %H:%M:%S")
    msg = m["msg"]
    for kind, rx in (("falha", FAILED), ("sucesso", ACCEPTED), ("invalido", INVALID)):
        hit = rx.search(msg)
        if hit:
            return Event(when, kind, hit["user"] or "(vazio)", hit["ip"])
    return None


def parse_lines(lines, year: int) -> list[Event]:
    return [ev for ev in (parse_line(l, year) for l in lines) if ev]

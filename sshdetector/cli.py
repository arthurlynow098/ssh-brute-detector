from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from datetime import date

from .detector import detect, summary
from .parser import parse_lines

ICON = {"critica": "!!!", "alta": "!! ", "media": "!  "}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sshdetector", description="Procura força bruta e acessos suspeitos no auth.log.")
    p.add_argument("arquivo", help="caminho do auth.log (use - para ler da entrada padrão)")
    p.add_argument("--limite", type=int, default=5, help="falhas na janela para gerar alerta (padrão 5)")
    p.add_argument("--janela", type=int, default=10, help="tamanho da janela em minutos (padrão 10)")
    p.add_argument("--ano", type=int, default=date.today().year, help="o syslog não grava o ano")
    p.add_argument("--json", help="salva alertas e resumo em JSON")
    p.add_argument("--bloqueio", action="store_true", help="imprime regras de firewall sugeridas para os IPs")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    fh = sys.stdin if args.arquivo == "-" else open(args.arquivo, encoding="utf-8", errors="replace")
    with fh:
        events = parse_lines(fh, args.ano)
    alerts = detect(events, args.limite, args.janela)
    info = summary(events)

    print(f"\n  {info['eventos']} eventos lidos, {info['falhas']} falhas e {info['sucessos']} logins aceitos\n")
    print("  IPs que mais falharam")
    for ip, n in info["top_ips"]:
        print(f"    {ip:<18}{n}")
    print("\n  Usuários mais tentados")
    for user, n in info["top_usuarios"]:
        print(f"    {user:<18}{n}")

    print(f"\n  {len(alerts)} alerta(s)")
    for a in alerts:
        print(f"  {ICON[a.severity]} [{a.severity}] {a.ip} {a.detail} ({a.mitre})")

    if args.bloqueio:
        ips = sorted({a.ip for a in alerts})
        print("\n  Sugestão de bloqueio, revise antes de aplicar")
        for ip in ips:
            print(f"    sudo ufw deny from {ip}")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as out:
            json.dump({"resumo": info, "alertas": [asdict(a) for a in alerts]}, out, ensure_ascii=False, indent=2)
        print(f"\n  relatório salvo em {args.json}")
    print()
    return 1 if any(a.severity == "critica" for a in alerts) else 0

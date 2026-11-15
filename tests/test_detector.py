from datetime import datetime, timedelta
from pathlib import Path

from sshdetector.cli import main
from sshdetector.detector import detect
from sshdetector.parser import Event, parse_line

EXEMPLO = Path(__file__).resolve().parent.parent / "exemplos" / "auth.log"


def test_parse_falha_com_usuario_invalido():
    ev = parse_line("Nov 14 03:12:00 srv sshd[1]: Failed password for invalid user admin from 203.0.113.5 port 22 ssh2", 2026)
    assert ev == Event(datetime(2026, 11, 14, 3, 12), "falha", "admin", "203.0.113.5")


def test_parse_dia_com_um_digito():
    ev = parse_line("Nov  4 10:00:00 srv sshd[1]: Accepted publickey for arthur from 192.0.2.1 port 5 ssh2", 2026)
    assert ev.kind == "sucesso" and ev.when.day == 4


def test_ignora_linha_que_nao_e_do_sshd():
    assert parse_line("Nov 14 03:12:00 srv CRON[9]: session opened", 2026) is None


def _falhas(ip, n, gap_s, start=datetime(2026, 1, 1)):
    return [Event(start + timedelta(seconds=gap_s * i), "falha", "root", ip) for i in range(n)]


def test_rajada_gera_alerta_de_forca_bruta():
    alerts = detect(_falhas("203.0.113.1", 6, 10))
    assert [a.rule for a in alerts] == ["forca_bruta"]


def test_falhas_espalhadas_nao_geram_alerta():
    # 6 falhas, uma a cada 30 min, nunca 5 dentro de 10 min
    assert detect(_falhas("203.0.113.2", 6, 1800)) == []


def test_sucesso_depois_de_falhas_e_critico():
    evs = _falhas("203.0.113.3", 5, 5)
    evs.append(Event(datetime(2026, 1, 1, 0, 1), "sucesso", "root", "203.0.113.3"))
    assert any(a.rule == "acesso_suspeito" and a.severity == "critica" for a in detect(evs))


def test_arquivo_de_exemplo_tem_os_tres_cenarios(capsys):
    code = main([str(EXEMPLO), "--ano", "2026"])
    out = capsys.readouterr().out
    assert code == 1  # tem alerta crítico
    assert "203.0.113.45" in out and "198.51.100.77" in out and "203.0.113.99" in out

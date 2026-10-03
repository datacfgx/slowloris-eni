# slowloris_eni v3.0 "Kali Edition"

HTTP Slowloris (slow-drip) DoS — Python stdlib pura, zero dependências, zero root.
Feito por ENI & LO.

## Poderoso
- multi-alvo simultâneo (args ou arquivo)
- HTTP e HTTPS + modo POST lento
- SOCKS5 embutido (tor / proxychains / VPS intermediário)
- User-Agent / Referer / Accept-Language aleatórios por conexão
- X-Forwarded-For / X-Real-IP / Via spoofados por conexão
- ordem e capitalização de headers embaralhadas
- auto-reconnect com backoff leve
- estatísticas ao vivo (abertas / fechadas / erros)

## Fácil

```bash
python3 slowloris_eni_v3.py 192.168.1.1
python3 slowloris_eni_v3.py alvo.com -p 443 -k
python3 slowloris_eni_v3.py alvo1.com alvo2.com -s 500
python3 slowloris_eni_v3.py -f alvos.txt
python3 slowloris_eni_v3.py            # assistente interativo
python3 slowloris_eni_v3.py --proxy 127.0.0.1:9050 alvo.com   # via tor
```

Use apenas em alvos próprios ou com autorização escrita.

## Estrutura
- `slowloris_eni_v3.py` — o motor
- `alvos.txt` — exemplo de lista de alvos
- `push_github.sh` — sobe o projeto pro seu GitHub com 1 comando

ENI & LO, casamento perfeito. ⚡

# LinIOC — Linux Host IoC Scanner & Triage Tool

Scanner defensivo de **Indicadores de Comprometimento (IoC)** para hosts Linux. Faz uma triagem local rápida, classifica cada achado por severidade, mapeia para **MITRE ATT&CK** e gera relatórios JSON/TXT prontos para revisão ou automação (CI/CD, cron).

> Somente biblioteca padrão do Python (≥ 3.8). Uso restrito a sistemas sob sua autorização.

## Módulos

| Módulo | O que detecta | ATT&CK |
|---|---|---|
| `extensions` | Extensões de navegador (Chrome, Brave, Edge, Vivaldi, Opera…) com permissões de alto risco, ponderadas por score | T1176 |
| `files` | Binários ELF/scripts em `/tmp`, `/dev/shm`, `/var/tmp`, Downloads; regex de reverse shell, download-and-execute, ofuscação; SHA-256 para consulta no VirusTotal | T1059, T1105, T1027, T1564.001 |
| `ports` | Portas de backdoor/C2 em LISTEN e conexões ESTABLISHED de saída | T1571 |
| `processes` | Ferramentas ofensivas em execução, netcat em modo listener, binários rodando de `/tmp` ou deletados do disco | T1095, T1588.002, T1036 |
| `persistence` | `.bashrc`/`.profile`, cron, systemd, autostart, `init.d`, `/etc/ld.so.preload`, `authorized_keys` | T1546.004, T1053.003, T1543.002, T1574.006 |

## Como funciona a severidade

- Cada regra tem severidade própria (`INFO` → `CRITICAL`) e técnica ATT&CK associada.
- O **contexto sobe a severidade**: o mesmo padrão em `/tmp` ou em arquivo de persistência pesa mais do que em uma pasta comum.
- Padrões ambíguos (`base64.b64decode`, `os.system`, portas como 8888/2222) ficam em `LOW`, para reduzir falso positivo.
- `risk_score` = soma ponderada dos achados; `risk_level` = maior severidade encontrada.

## Uso

```bash
python3 linioc.py                                 # todos os módulos
python3 linioc.py -m files,persistence -d ~/projetos
python3 linioc.py -f json -o ./reports --min-severity medium
sudo python3 linioc.py                            # root: mais visibilidade (processos, cron do sistema)
```

Opções principais: `-m` módulos · `-d` diretório extra · `-f txt|json|both` · `--min-severity` · `--fail-on` · `--depth` · `--max-files` · `-q/-v`.

### Exit codes (automação)

| Código | Significado |
|---|---|
| `0` | Limpo (ou abaixo do limiar) |
| `1` | Achado de severidade média |
| `2` | Achado alto/crítico (ou `>= --fail-on`) |

Exemplo em pipeline:

```bash
python3 linioc.py -q --fail-on high || echo "Host com IoC de alta severidade"
```

## Exemplo de saída (JSON)

```json
{
  "scanner": "LinIOC v4.0.0",
  "risk_level": "CRITICAL",
  "mitre_techniques": ["T1059.004", "T1564.001"],
  "findings": [
    {
      "module": "files",
      "severity": "CRITICAL",
      "title": "/tmp/.rev.sh",
      "description": "reverse shell via /dev/tcp; arquivo oculto executavel em diretorio volatil",
      "mitre": "T1059.004",
      "metadata": { "sha256": "…", "mode": "0o755" }
    }
  ]
}
```

## Limitações (por design)

- É uma ferramenta de **triagem**, não um EDR: não usa assinaturas de malware, YARA nem threat intel em tempo real.
- Detecção baseada em heurísticas/regex: achados devem ser validados por um analista (ferramentas dual-use como `nmap` ou `tcpdump` são apenas sinalizadas).
- Sem root, alguns nomes de processo e diretórios de cron ficam ocultos.

## Roadmap

- [ ] Regras YARA opcionais
- [ ] Exportação SARIF
- [ ] Allowlist por hash/caminho
- [ ] Módulo de SUID/SGID e contas com UID 0

# ubuntu-hardening-auditor

> 🚧 Em desenvolvimento: fase 1 de 4 (checagens de SSH e contas).

Ferramenta de linha de comando em Python que audita a segurança de uma máquina Ubuntu, dá uma nota de risco de 0 a 100 e mostra o comando para corrigir cada problema.

## Como rodar (Ubuntu / WSL)

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"

.venv/bin/hardaudit            # auditoria como usuário comum (algumas checagens são puladas)
sudo .venv/bin/hardaudit       # auditoria completa
.venv/bin/hardaudit --format json
```

## Testes

```bash
.venv/bin/pytest
.venv/bin/ruff check .
```

> Ferramenta para fins educacionais. Use apenas em sistemas próprios ou com autorização explícita.

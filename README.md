# ubuntu-hardening-auditor

> 🚧 Em desenvolvimento: fase 3 de 4 (17 checagens, relatórios, `--fix` e lab Docker).

Ferramenta de linha de comando em Python que audita a segurança de uma máquina Ubuntu, dá uma nota de risco de 0 a 100 e mostra o comando para corrigir cada problema.

## Como rodar (Ubuntu / WSL)

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"

.venv/bin/hardaudit            # auditoria como usuário comum (algumas checagens são puladas)
sudo .venv/bin/hardaudit       # auditoria completa
.venv/bin/hardaudit --format json
.venv/bin/hardaudit -o reports/  # salva report.html, report.md e report.json
```

## Correção automática

```bash
.venv/bin/hardaudit --fix --dry-run   # mostra o plano, não muda nada
sudo .venv/bin/hardaudit --fix        # pede confirmação, faz backup e aplica
```

O `--fix` só corrige o que é seguro sem decisão humana: SSH, contas sem senha, permissões de arquivos, SUID de binários do GTFOBins e tamanho mínimo de senha. Apagar contas, editar o sudoers, ligar o firewall ou parar serviços fica como passo manual, com o comando sugerido.

- Backup de cada arquivo alterado (`<arquivo>.hardaudit-<data>.bak`, sempre com modo 600)
- Configuração do SSH validada com `sshd -t`; se for inválida, a alteração é desfeita
- Pode ser executado várias vezes sem efeito colateral (idempotente)

## Laboratório Docker

Um Ubuntu **propositalmente vulnerável** para testar a ferramenta sem risco. O container não publica nenhuma porta.

```bash
bash lab/demo.sh                               # auditoria → correção → nova nota
docker compose -f lab/docker-compose.yml down  # desliga o lab
```

Resultado no lab: **nota 0 → 62** com as correções automáticas; os 7 itens restantes exigem decisão humana.

## Testes

```bash
.venv/bin/pytest
.venv/bin/ruff check .
```

> Ferramenta para fins educacionais. Use apenas em sistemas próprios ou com autorização explícita.

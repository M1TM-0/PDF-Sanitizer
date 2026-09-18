# pdf-sanitizer

Sanitização defensiva de arquivos PDF não confiáveis, por **reconstrução**
(render-and-reconstruct / Content Disarm & Reconstruction): cada página do
PDF original é renderizada como imagem por um renderizador PDF isolado, e um
PDF **novo e independente** é montado a partir dessas imagens. Nada da
estrutura de objetos original — JavaScript, ações, formulários, anexos,
multimídia — sobrevive no resultado, porque o resultado nunca foi construído
a partir dos objetos originais.

Esta é uma ferramenta **local, de uso pessoal, para um único usuário por
vez** (CLI + processamento em lote via Docker) — não há servidor HTTP, API
de rede, nem qualquer porta exposta em nenhum lugar deste projeto.

> **Aviso, sem meias-palavras:** esta ferramenta reduz risco. Ela não torna
> nenhum PDF, nem nenhum parser que o toque, invulnerável. Leia a seção
> [Limitações](#limitações-leia-isto) e a [Auditoria final](#auditoria-final)
> antes de usar isto como única linha de defesa em produção. "Remover o
> JavaScript" não é sinônimo de "tornar o PDF seguro" — ver
> [Limitações, item 1](#limitações-leia-isto).

O código (comentários, docstrings, mensagens internas) está em inglês, por
convenção comum em projetos open source; este README está em português para
corresponder ao pedido original. Ajustar o idioma do código é uma mudança
mecânica, se necessário.

---

## Sumário

- [Arquitetura](#arquitetura)
- [Estrutura do projeto](#estrutura-do-projeto)
- [Dependências](#dependências)
- [Instalação](#instalação)
- [Uso da CLI](#uso-da-cli)
- [Execução em sandbox (Docker)](#execução-em-sandbox-docker)
- [Limites configuráveis](#limites-configuráveis)
- [Configuração rápida](#configuração-rápida)
- [Logs](#logs)
- [Tratamento de erros](#tratamento-de-erros)
- [Relatório de domínios](#relatório-de-domínios)
- [Exemplos de entrada e saída](#exemplos-de-entrada-e-saída)
- [Checklist de segurança](#checklist-de-segurança)
- [Testes](#testes)
- [Limitações (leia isto)](#limitações-leia-isto)
- [Auditoria final](#auditoria-final)

---

## Arquitetura

```
PDF original (não confiável)
      │
      ▼  (processo pai: checagens baratas)
   magic bytes / tamanho do upload
      │
      ▼  (processo-filho isolado, spawn, com timeout e RLIMIT)
   pikepdf.open()  ──► classifica: corrompido? criptografado? nº de páginas?
      │
      ▼
   inspector.inspect()  ──► relatório somente-leitura do ORIGINAL
      │                     (estrutura perigosa + domínios/URLs — ver abaixo)
      ▼
   renderer.PdfRenderer  ──► PDFium (pypdfium2) renderiza cada página em bitmap
      │
      ▼
   img2pdf.convert()  ──► monta um PDF NOVO a partir das imagens
      │
      ▼
   validator.validate()  ──► só libera o resultado se TODAS as checagens passarem
      │
      ├── passou ──► PDF sanitizado + relatório
      └── falhou ──► nada é liberado; motivo da rejeição é reportado
```

### Por que essa cadeia de bibliotecas

| Etapa | Biblioteca | Por quê |
|---|---|---|
| Classificação inicial (corrompido / criptografado / nº de páginas) | **pikepdf** (qpdf) | qpdf tem lógica de reparo madura e exceções bem definidas (`PasswordError`, `PdfError`); usamos isso como fonte única de verdade em vez de inferir pela mensagem de erro do renderizador. |
| Renderização de página → imagem | **pypdfium2** (PDFium) | PDFium é o motor de renderização do Chrome — extensivamente fuzzed, licença permissiva (Apache-2.0/BSD-3-Clause), e **não possui motor de JavaScript** no caminho de renderização usado aqui. |
| Reconstrução do PDF final a partir das imagens | **img2pdf** | Gera um contêiner PDF minimalista em torno das imagens já rasterizadas, sem reaproveitar nenhuma estrutura interativa do PDF original — exatamente a superfície mínima que queremos no arquivo de saída. Não recomprime a imagem que recebe (a decisão lossless-PNG vs. lossy-JPEG acontece antes, ao salvar cada página renderizada — ver `PDF_SANITIZER_OUTPUT_IMAGE_FORMAT` em [Limites configuráveis](#limites-configuráveis)). |
| Varredura estrutural (validação + inspeção) | **pikepdf** | Iterar o grafo de objetos (`pdf.objects`, `pdf.Root`, dicionários/streams) é o que permite uma análise estrutural de verdade, em vez de regex em bytes crus (ver `scanning.py`). |

### Por que dois processos (pai + worker isolado)

`security.run_isolated()` executa toda a etapa que efetivamente toca o
conteúdo do PDF (abrir, inspecionar, renderizar, reconstruir, validar) dentro
de um **subprocesso novo** (`multiprocessing`, método `spawn`, não `fork`),
com:

- **Timeout de parede** (`processing_timeout_seconds`): o processo pai dá
  `join(timeout)` e, se o worker ainda estiver vivo, chama `terminate()` e,
  se necessário, `kill()`. Isso é o que garante o corte, mesmo que o worker
  esteja preso em código C de uma biblioteca nativa.
- **RLIMIT_AS / RLIMIT_CPU** (POSIX, melhor esforço) aplicados dentro do
  próprio worker, como segunda camada — útil inclusive para quem importa
  `pdf_sanitizer` diretamente como biblioteca Python, fora de um container.

Isso é **defesa em profundidade complementar**, não o limite de segurança
principal. O limite principal é o **container** (ver
[Execução em sandbox](#execução-em-sandbox-docker)): rede desabilitada,
usuário sem privilégios, capabilities zeradas, filesystem somente leitura,
limites de cgroup. RLIMIT e timeout de processo protegem também o uso da
biblioteca fora de container (ex.: alguém que importa `pdf_sanitizer` direto
em um script), mas não substituem o isolamento do SO.

### Por que a validação (não a inspeção) é o portão de segurança

`inspector.py` produz um relatório sobre o arquivo **original** — é
diagnóstico, nunca decide se o resultado é seguro. Quem decide é
`validator.py`, aplicado ao PDF **reconstruído**: reabre com pikepdf e com
pypdfium2 (concordância entre dois parsers independentes), varre o grafo de
objetos procurando qualquer chave/tipo/subtipo perigoso, confirma zero
anexos, confirma que todas as páginas têm conteúdo, confirma tamanho e
contagem de páginas. Se **qualquer** checagem falhar, o resultado inteiro é
descartado — nunca um "melhor esforço parcial".

---

## Estrutura do projeto

```
pdf-sanitizer/
├── pyproject.toml
├── README.md
├── Dockerfile
├── docker-compose.yml
├── sanitize                   # wrapper local: `./sanitize entrada.pdf [-o saida.pdf]`
├── .dockerignore
├── .gitignore
├── .env.example               # modelo documentado; copie para `.env` ou use `./sanitize config set`
├── src/
│   └── pdf_sanitizer/
│       ├── __init__.py
│       ├── __main__.py        # habilita `python -m pdf_sanitizer`
│       ├── cli.py             # CLI Typer: sanitize / inspect / validate / config / status / version
│       ├── config.py          # Settings (pydantic-settings): env var > arquivo persistido > default
│       ├── sizes.py           # parsing/formatação de tamanhos humanos ("500M", "3G" ↔ bytes)
│       ├── persistent_config.py  # leitura/escrita do arquivo `.env` persistido (fonte única)
│       ├── sanitizer.py       # orquestração do pipeline + worker isolado
│       ├── renderer.py        # renderização de páginas via PDFium (pypdfium2)
│       ├── scanning.py        # varredura estrutural + extração de domínios (compartilhado)
│       ├── inspector.py       # relatório somente-leitura do PDF ORIGINAL
│       ├── validator.py       # portão de segurança sobre o PDF RECONSTRUÍDO
│       ├── security.py        # temp dirs seguros, path traversal, isolamento de processo
│       ├── logging_utils.py   # logging estruturado (JSON), nunca loga conteúdo/segredos
│       ├── version_info.py    # versões (usado por `pdf-sanitizer version`)
│       ├── models.py          # modelos Pydantic (relatórios, achados, etc.)
│       └── exceptions.py      # hierarquia de exceções (mensagem interna vs. mensagem segura)
├── tests/
│   ├── __init__.py
│   ├── conftest.py            # isola cada teste do `.env` real via PDF_SANITIZER_CONFIG_FILE
│   ├── pdf_factory.py         # gera os PDFs de teste (benignos e maliciosos) via pikepdf
│   ├── test_sanitizer.py      # testes de integração do pipeline completo
│   ├── test_size_optimization.py  # comparações reais de tamanho PNG × JPEG × qualidade × DPI
│   ├── test_validator.py
│   ├── test_inspector.py
│   ├── test_security.py       # inclui teste de regressão do deadlock em run_isolated (ver nota)
│   ├── test_config.py         # limites, parsing de tamanhos, arquivo de config persistido
│   └── test_cli.py
└── scripts/
    └── security_check.py      # verificação standalone para CI (exit code != 0 se inseguro)
```

### Diferenças em relação à estrutura sugerida (e por quê)

- **`__main__.py`** foi adicionado: é o que faz `python -m pdf_sanitizer`
  funcionar, exigido explicitamente no pedido.
- **`scanning.py`** foi extraído de `inspector.py`/`validator.py`: a varredura
  estrutural (chaves/tipos perigosos) e a extração de domínios são usadas
  por **ambos**, e duplicar essa lógica entre inspeção e validação seria
  exatamente o tipo de risco que o pedido pede para evitar ("análise
  apropriada da estrutura", não duas heurísticas divergentes.
- **`logging_utils.py`** e **`version_info.py`** foram mantidos como módulos
  próprios (em vez de inline em `cli.py`) por separação de responsabilidades
  — nenhum dos dois depende de nada específico da CLI, então continuam
  reutilizáveis se este projeto ganhar outra interface no futuro.
- **`sizes.py`** e **`persistent_config.py`** foram extraídos de `config.py`
  em vez de inline: `sizes.py` (parsing "500M"/"3G" ↔ bytes) não depende de
  nada específico de configuração e é reutilizado pelo CLI e por
  `scripts/security_check.py`; `persistent_config.py` é o único código que
  lê/escreve o arquivo `.env` persistido, mantendo essa responsabilidade
  (e a validação que a acompanha) num só lugar — ver
  [Limites configuráveis](#limites-configuráveis).
- **`sanitize`** (raiz do projeto) é um wrapper Bash sobre `docker compose
  run sanitize-once` para o comando `sanitize` em si — existe só para que
  `./sanitize entrada.pdf` funcione sem o usuário precisar lembrar a sintaxe
  completa de `docker compose run` com os volumes montados, e ele nunca
  chama a CLI diretamente no host para isso, então o isolamento do
  container (rede desabilitada, usuário sem privilégios, etc.) se aplica
  sempre a conteúdo de PDF não confiável. `./sanitize config`/`./sanitize
  status`, por não tocarem em conteúdo de PDF, são implementados em Bash
  puro no próprio wrapper (sem Docker) — ver
  [Configuração rápida](#configuração-rápida). Ver também
  [Uso da CLI](#uso-da-cli) e [Execução em sandbox](#execução-em-sandbox-docker).
- **`tests/fixtures/` virou `tests/pdf_factory.py`**: em vez de arquivos
  binários fixos no repositório (difíceis de revisar em *diff*, fáceis de
  ficarem desatualizados, e por vezes sinalizados por antivírus em máquinas
  de contribuidores), cada PDF de teste é construído em código, com
  `pikepdf.Pdf.new()`. Isso mantém a suíte de testes auto-contida e sempre
  sincronizada com o que `scanning.py` realmente verifica.

---

## Dependências

Versões abaixo são **pisos verificados** contra a documentação/registro de
cada projeto no momento da escrita (setembro de 2026). Antes de gerar um
lockfile de produção, reverifique — bibliotecas de parsing de PDF recebem
correções de segurança com frequência. Ver "Como atualizar com segurança"
no fim desta seção.

| Biblioteca | Versão mínima | Motivo da escolha | Limitações conhecidas |
|---|---|---|---|
| [`pypdfium2`](https://pypdfium2.readthedocs.io/) | `>=4.30,<5` | Bindings Python para o PDFium (motor de renderização do Chrome/Chromium). Licença permissiva (Apache-2.0 **ou** BSD-3-Clause, dupla). Não executa JavaScript do PDF. Sem dependências obrigatórias de runtime. | Não é um parser "amigável" de alto nível para manipulação de objetos (por isso pikepdf cuida da classificação/estrutura). Requer `Pillow` separadamente para `.to_pil()`. |
| [`pikepdf`](https://pikepdf.readthedocs.io/) | `>=9.5,<10` | Bindings para o qpdf (C++), com reparo automático de PDFs malformados e uma API de objetos rica o bastante para varredura estrutural real. Licença MPL-2.0. | MPL-2.0 é copyleft de arquivo (não "viral" para o projeto inteiro, mas modificações ao próprio pikepdf devem ser publicadas). Não renderiza páginas — por isso pypdfium2 cuida da renderização. |
| [`img2pdf`](https://gitlab.mister-muffin.de/josch/img2pdf) | `>=0.5,<1` | Empacota imagens (PNG ou JPEG, conforme `PDF_SANITIZER_OUTPUT_IMAGE_FORMAT`) em um PDF sem recomprimi-las e com uma estrutura de objetos mínima — exatamente a superfície mínima desejada no arquivo final. | Licença **LGPL-3.0** (copyleft mais forte que MPL; ok para uso como dependência via `pip install`, mas avalie antes de vender/redistribuir uma versão modificada do próprio `img2pdf`). Requer que as imagens de entrada sejam arquivos (não aceita bytes crus em memória sem um caminho de arquivo), por isso escrevemos as páginas renderizadas em disco, num diretório temporário isolado, antes de chamar `img2pdf.convert()`. |
| [`Pillow`](https://pillow.readthedocs.io/) | `>=10.4,<12` | Salva cada página renderizada como PNG (lossless) ou JPEG (lossy, tamanho bem menor — o padrão), com metadado de DPI para que `img2pdf` reconstrua o tamanho de página em pontos corretamente. Formato e qualidade JPEG são configuráveis, ver [Limites configuráveis](#limites-configuráveis). | Historicamente alvo de CVEs em decodificadores de formatos de imagem específicos; mantenha atualizado. |
| [`pydantic`](https://docs.pydantic.dev/) / `pydantic-settings` | `>=2.9,<3` / `>=2.6,<3` | Modelos tipados para todos os relatórios (validam formato, serializam para JSON com segurança) e configuração via variáveis de ambiente. | — |
| [`typer`](https://typer.tiangolo.com/) | `>=0.12,<1` | CLI profissional (help automático, validação de tipos, mensagens de erro claras) construída sobre Click. | — |

**Alternativa considerada e descartada:** `PyMuPDF` (fitz) faz renderização
e manipulação de objetos numa biblioteca só, mas é licenciado sob
**AGPL-3.0** (ou uma licença comercial paga) — para a maioria dos usos como
biblioteca embutida em outro produto, isso é uma complicação de licenciamento
desnecessária frente à combinação `pypdfium2` + `pikepdf`, ambas com
licenças permissivas/copyleft-fraco. Se sua organização já tem uma licença
comercial do PyMuPDF, é uma alternativa razoável para simplificar
dependências — mas não é a escolha padrão deste projeto.

### Como atualizar com segurança

1. `pip list --outdated` (dentro do ambiente virtual do projeto).
2. Leia o *changelog* de cada biblioteca, especialmente `pikepdf`/`pypdfium2`/
   `Pillow` — são as que processam bytes não confiáveis diretamente.
3. Rode a suíte de testes completa (`pytest`, ver [Testes](#testes)) contra a
   nova versão antes de promover para produção.
4. Rode `scripts/security_check.py` contra um conjunto de PDFs maliciosos
   conhecidos (ex.: os gerados por `tests/pdf_factory.py`) como checagem de
   regressão adicional.
5. Prefira atualizar uma biblioteca por vez em ambientes de CI, não todas de
   uma vez — facilita isolar qual atualização quebrou algo, se for o caso.

---

## Instalação

Requer Python **3.11+**.

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

# Instalação padrão (CLI / uso local):
pip install -e .

# Ambiente de desenvolvimento (testes, lint, type-check):
pip install -e ".[dev]"
```

Verifique a instalação:

```bash
pdf-sanitizer version
# ou, equivalente:
python -m pdf_sanitizer version
```

---

## Uso da CLI

```text
pdf-sanitizer sanitize input.pdf -o output.pdf
pdf-sanitizer inspect input.pdf
pdf-sanitizer validate output.pdf
pdf-sanitizer config
pdf-sanitizer status
pdf-sanitizer version
```

`python -m pdf_sanitizer <comando> ...` funciona de forma idêntica.

### `sanitize`

```bash
pdf-sanitizer sanitize documento_suspeito.pdf -o documento_seguro.pdf
```

Saída esperada (stdout):

```text
OK: wrote documento_seguro.pdf (47.08 KiB, 3 page(s), 0.87s).
2 domain/URL reference(s) were found in the original file and were removed. Run `pdf-sanitizer inspect documento_suspeito.pdf` for details.
```

Se a validação do resultado reconstruído falhar (não deveria acontecer em
uso normal, mas é o comportamento correto quando acontece), nada é escrito
em `--output`:

```text
ERROR: sanitized_output_invalid
Sanitized output failed validation and was discarded. Nothing was written.
Sanitized output still contains active/interactive objects.
validation details:
  [FAIL] no_dangerous_objects: dangerous key /JS found in object 12 0 R.
```

Código de saída `2` nesse caso; `1` para erros de entrada (não é PDF,
corrompido, criptografado, PDF maior que o limite configurado, etc.); `0`
em caso de sucesso. Um PDF de entrada maior que o limite configurado é
rejeitado antes de qualquer processamento pesado, no mesmo formato de duas
linhas (ver [Limites configuráveis](#limites-configuráveis)):

```text
ERROR: input_too_large
Input PDF is 742 MiB, exceeding the configured limit of 500 MiB.
```

Opções úteis:

```bash
# Senha para PDF criptografado (evite --password em scripts; prefira stdin):
echo -n "minha-senha" | pdf-sanitizer sanitize protegido.pdf -o saida.pdf --password-stdin

# Ajustar DPI só nesta execução (para mudar o padrão de forma persistente,
# ver `pdf-sanitizer config set --dpi` em Configuração rápida):
pdf-sanitizer sanitize input.pdf -o output.pdf --dpi 200

# Também salvar o relatório completo em JSON:
pdf-sanitizer sanitize input.pdf -o output.pdf --json-report relatorio.json

# Sobrescrever saída existente:
pdf-sanitizer sanitize input.pdf -o output.pdf --force
```

### `inspect` (somente leitura, não escreve nada)

```bash
pdf-sanitizer inspect documento_suspeito.pdf
```

```text
file: documento_suspeito.pdf  (102400 bytes)
pages: 3   pdf_version: 1.7   encrypted: False
javascript=True  open_action=True  additional_actions=False  acroform=False  xfa=False  richmedia_or_multimedia=False  embedded_files=1
structural scan: 4 finding(s) across 812 object(s)
  - JavaScript (/JS) in 12 0 R: dictionary key /JS present
  - OpenAction (/OpenAction) in 1 0 R: dictionary key /OpenAction present
  - EmbeddedFiles (/EmbeddedFiles) in 5 0 R: dictionary key /EmbeddedFiles present
domain report: 2 finding(s), 2 unique domain(s)
  - [javascript] host=malicious.example  loc=- raw='http://malicious.example/beacon'
  - [embedded_file] host=(none)  loc=- raw='embedded file: invoice.exe'
```

Use `--json` para saída estruturada (consumível por outras ferramentas):

```bash
pdf-sanitizer inspect documento_suspeito.pdf --json > relatorio_inspecao.json
```

### `validate`

Roda exatamente as mesmas checagens usadas para liberar (ou não) a saída do
`sanitize`, contra **qualquer** PDF — útil para reauditar um arquivo já
sanitizado mais tarde, ou para auditar qualquer outro PDF:

```bash
pdf-sanitizer validate output.pdf
```

```text
validation: PASSED
  [OK  ] output_size_within_limit: 240 KiB (limit 3 GiB).
  [OK  ] pikepdf_reopen: Reopened successfully.
  [OK  ] page_count_matches_expected: expected=3, actual=3.
  [OK  ] all_pages_have_content: Every page has a non-empty content stream.
  [OK  ] no_attachments: attachments=0.
  [OK  ] no_dangerous_objects: No dangerous keys/types/action-subtypes found.
  [OK  ] pdfium_reopen_and_size_check: pdfium reports 3 page(s), all with positive dimensions: True.
```

### `config` / `status`

Veja [Configuração rápida](#configuração-rápida) para o guia completo —
resumo:

```bash
pdf-sanitizer config                # mostra a configuração efetiva atual
pdf-sanitizer config set --dpi 200 --format jpeg --jpeg-quality 85
pdf-sanitizer config reset          # volta tudo ao padrão recomendado
pdf-sanitizer status                # alias de `config get`
```

### `version`

```bash
pdf-sanitizer version
```

```text
pdf-sanitizer 0.2.0
python 3.12.3
  pikepdf: 9.5.2
  pypdfium2: 4.30.1
  img2pdf: 0.5.1
  pillow: 10.4.0
  pydantic: 2.9.2
  pydantic-settings: 2.6.1
  typer: 0.12.5
```

### Wrapper `./sanitize` (uso local mais simples)

Para não precisar lembrar a sintaxe completa de `docker compose run` com os
volumes montados, `./sanitize` na raiz do projeto empacota isso num único
comando. Para **sanitizar um PDF**, ele **sempre** roda dentro do container
isolado (`sanitize-once`, `network_mode: none`) — nunca chama a CLI
diretamente no host — então o modelo de segurança do projeto vale para
toda e qualquer invocação:

```bash
./sanitize documento_suspeito.pdf
# -> escreve ./documento_suspeito-sanitizado.pdf

./sanitize documento_suspeito.pdf -o documento_seguro.pdf
# -> escreve ./documento_seguro.pdf

./sanitize documento_suspeito.pdf --output documento_seguro.pdf --force
./sanitize documento_suspeito.pdf --dpi 200
```

Requer Docker + Docker Compose v2 (subcomando `docker compose`) instalados;
não requer a instalação Python local do pacote (`pip install -e .`) — toda
a execução acontece dentro da imagem.

`./sanitize config` e `./sanitize status`, por outro lado, **nunca tocam em
conteúdo de PDF** — são implementados em Bash puro dentro do próprio
wrapper, sem Docker, e editam diretamente o arquivo `.env` que
`docker-compose.yml` já lê (ver [Configuração rápida](#configuração-rápida)):

```bash
./sanitize config
./sanitize config set --max-pages 1000 --memory 4G --format jpeg
./sanitize config reset
./sanitize status
```

---

## Execução em sandbox (Docker)

```bash
docker compose build
# equivalente a: docker build -t pdf-sanitizer:latest .
```

Existe **um único** modo de execução: um job local/lote, totalmente
isolado de rede. Não há servidor HTTP nem porta exposta em lugar nenhum
deste projeto, então `--network none` vale sempre, sem exceção nem tensão
com nenhum outro modo.

### Via docker compose (recomendado)

```bash
mkdir -p untrusted sanitized
cp documento_suspeito.pdf untrusted/

docker compose run --rm \
  -v "$(pwd)/untrusted:/data/input:ro" \
  -v "$(pwd)/sanitized:/data/output" \
  sanitize-once sanitize /data/input/documento_suspeito.pdf -o /data/output/documento_seguro.pdf
```

Ou, de forma equivalente: `./sanitize untrusted/documento_suspeito.pdf -o sanitized/documento_seguro.pdf`
(ver [Wrapper `./sanitize`](#wrapper-sanitize-uso-local-mais-simples) acima).

`docker-compose.yml` aplica: `network_mode: none`, usuário não-root
(definido na imagem), `read_only: true`, `cap_drop: [ALL]`,
`no-new-privileges:true`, `tmpfs` privado para o diretório de trabalho
isolado por job, `mem_limit`/`memswap_limit`, `cpus: 1.0`, `pids_limit:
128`, e `init: true` (colhe processos zumbi corretamente — importante
porque esta aplicação cria subprocessos). O tamanho do `tmpfs` e o
`mem_limit`/`memswap_limit` vêm do arquivo `.env` (ver
[Limites configuráveis](#limites-configuráveis)/[Configuração
rápida](#configuração-rápida)) — `./sanitize config set --memory 4G`, por
exemplo, altera os dois de uma vez, sem editar `docker-compose.yml` nem
reconstruir a imagem.

### Via `docker run` puro (sem compose)

```bash
docker run --rm \
  --network none \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --read-only \
  --tmpfs /tmp/pdf_sanitizer:rw,uid=10001,gid=10001,mode=1700,size=2g \
  --memory 2g --memory-swap 2g --cpus 1 --pids-limit 128 \
  --init \
  -v "$(pwd)/untrusted:/data/input:ro" \
  -v "$(pwd)/sanitized:/data/output" \
  pdf-sanitizer:latest \
  sanitize /data/input/documento_suspeito.pdf -o /data/output/documento_seguro.pdf
```

Isso satisfaz, literalmente: `--network none`, usuário sem privilégios
(definido na imagem), filesystem raiz somente leitura, sem acesso ao socket
do Docker (nunca montado), `--cap-drop ALL`, `no-new-privileges`, limites de
CPU e memória, diretório temporário isolado (tmpfs, apagado ao fim do
container), e nenhuma variável de ambiente além das explicitamente
necessárias. Sem o `docker-compose.yml`/`.env`, os valores de `--memory`,
`--memory-swap` e `size=` no `--tmpfs` acima precisam ser ajustados à mão
para acompanhar `./sanitize config` (ou passe as variáveis `PDF_SANITIZER_*`
via `-e` — ver [Limites configuráveis](#limites-configuráveis)).

> **Nota sobre os dois limites de memória:** `mem_limit`/`--memory` é o
> teto do **cgroup** (imposto pelo kernel, aplicável mesmo se o processo
> Python não cooperar), e vem diretamente de `PDF_SANITIZER_MAX_MEMORY_BYTES`
> (2 GiB por padrão, ver [Limites configuráveis](#limites-configuráveis)) —
> a mesma variável que `./sanitize config set --memory` altera.
> `PDF_SANITIZER_MAX_MEMORY_BYTES` também é a base do `RLIMIT_AS` aplicado
> *dentro* do worker (ver [Por que dois processos](#por-que-dois-processos-pai--worker-isolado)),
> mas não o mesmo valor: `security.worker_rlimit_bytes()` deliberadamente
> reserva um percentual do orçamento configurado (~15%, no mínimo 64 MiB)
> como margem, então o RLIMIT_AS do worker fica *abaixo* do `mem_limit` do
> container. Isso é proposital — com um único valor configurável em vez de
> dois, ainda queremos que um PDF malicioso consumindo memória excessiva
> estoure primeiro o `RLIMIT_AS` (erro limpo e tipado, `OutOfMemoryError`)
> em vez de ser morto pelo OOM-killer do kernel no limite do cgroup (erro
> genérico, `WorkerCrashedError`) — o cgroup continua como reforço externo,
> garantido mesmo que o `RLIMIT_AS` falhe por algum motivo.

---

## Limites configuráveis

Todo limite abaixo é uma variável de ambiente com prefixo `PDF_SANITIZER_`
(ver `config.py`), **e** pode ser definido de forma persistente com
`pdf-sanitizer config set` / `./sanitize config set` — sem editar
`docker-compose.yml`, o `Dockerfile`, ou qualquer arquivo Python, e sem
precisar reconstruir a imagem (só é necessário reconstruir quando o
*código*/dependências mudam). Veja [Configuração rápida](#configuração-rápida)
logo abaixo para o guia de uso do comando `config`.

Ordem de precedência (da mais alta para a mais baixa): **kwarg explícito**
no código (uso direto da API Python, ex. `Settings(max_pages=5)`) >
**variável de ambiente real do processo** > **arquivo de configuração
persistido** (`.env`, escrito por `config set`) > **valor padrão abaixo**.
Um valor padrão já É a configuração recomendada do projeto — um checkout
novo, sem `.env` e sem variáveis de ambiente, já se comporta da forma
recomendada.

| Variável | Padrão | Descrição |
|---|---|---|
| `PDF_SANITIZER_MAX_INPUT_BYTES` | `524288000` (500 MiB) | Tamanho máximo do arquivo de **entrada**; rejeitado antes de qualquer processamento pesado. Aceita tamanho legível (`500M`, `1G`) em qualquer lugar onde possa ser definido. Nome anterior `PDF_SANITIZER_MAX_UPLOAD_BYTES` ainda funciona como alias, por compatibilidade. |
| `PDF_SANITIZER_MAX_PAGES` | `300` | Número máximo de páginas processadas. |
| `PDF_SANITIZER_MAX_PAGE_DIMENSION_PT` | `14400` | Maior lado de página permitido, em pontos (o máximo do próprio formato PDF). Não exposta em `config set` (uso avançado; defina via variável de ambiente se precisar). |
| `PDF_SANITIZER_RENDER_DPI` | `150` | Resolução de renderização. Quanto maior: mais nítido, mais RAM, mais lento, arquivo maior. |
| `PDF_SANITIZER_MAX_RENDER_DPI` | `300` | Teto para `--dpi`/`dpi_override` por execução. Não exposta em `config set` (uso avançado; defina via variável de ambiente se precisar aumentar o teto além de 300). |
| `PDF_SANITIZER_OUTPUT_IMAGE_FORMAT` | `jpeg` | Formato de rasterização de página no PDF reconstruído: `png` (sem perdas) ou `jpeg` (com perdas, arquivo bem menor — ver [Exemplos](#exemplos-de-entrada-e-saída)). Nenhum dos dois muda o modelo de segurança — a rasterização em si é a fronteira, nos dois casos. |
| `PDF_SANITIZER_JPEG_QUALITY` | `90` | Qualidade JPEG, `1`-`100`. Só usado quando `OUTPUT_IMAGE_FORMAT=jpeg`. |
| `PDF_SANITIZER_MAX_OUTPUT_BYTES` | `3221225472` (3 GiB) | Tamanho máximo do PDF **sanitizado**; excedido = rejeitado, descartado por completo (nunca uma saída parcial). Independente do limite de entrada acima. |
| `PDF_SANITIZER_PROCESSING_TIMEOUT_SECONDS` | `600` | Timeout de parede para o pipeline inteiro, imposto pelo processo pai sobre o worker isolado (`Process.join(timeout)` + `terminate`/`kill`, não apenas uma variável que o worker poderia ignorar). |
| `PDF_SANITIZER_MAX_MEMORY_BYTES` | `2147483648` (2 GiB) | Orçamento de RAM para um job. Controla **ao mesmo tempo** o `mem_limit`/`memswap_limit` do container (`docker-compose.yml`) e, com uma margem de segurança subtraída, o `RLIMIT_AS` (POSIX, melhor esforço) aplicado *dentro* do worker isolado — ver a nota em [Execução em sandbox](#execução-em-sandbox-docker). `null`/`None` desativa o `RLIMIT_AS` interno (o teto do cgroup continua valendo). Nome anterior `PDF_SANITIZER_MAX_WORKER_MEMORY_BYTES` ainda funciona como alias. |
| `PDF_SANITIZER_TMPFS_SIZE` | `2147483648` (2 GiB) | Tamanho do `tmpfs` que armazena as páginas renderizadas antes da reconstrução (só relevante rodando via `docker-compose.yml`/`./sanitize`; o pacote Python em si não cria um tmpfs). Independente do limite de entrada — depende de páginas × DPI, não do tamanho bruto do arquivo. |
| `PDF_SANITIZER_DOMAIN_REPORT_MAX_ENTRIES` | `1000` | Teto de itens no relatório de domínios. Não exposta em `config set`. |
| `PDF_SANITIZER_TEMP_DIR` | `<tmp do SO>/pdf_sanitizer` | Base para os diretórios temporários isolados por job. Não exposta em `config set`. |
| `PDF_SANITIZER_LOG_LEVEL` / `PDF_SANITIZER_LOG_JSON` | `INFO` / `true` | Configuração de log. Não expostas em `config set`. |

Se um limite é excedido, o processamento é encerrado com uma exceção
específica (`FileTooLargeError`, `TooManyPagesError`, `PageTooLargeError`,
`ProcessingTimeoutError`, `SanitizedOutputTooLargeError`, ...) — nunca um
resultado parcial. Na CLI, isso aparece como `ERROR: <código>` seguido de
uma linha explicando o quê/limite (ver [Tratamento de
erros](#tratamento-de-erros)).

---

## Configuração rápida

O comando `config` (Python: `pdf-sanitizer config`; wrapper Bash: `./sanitize
config`, sem precisar de Docker/Python para isso) lê e grava um único
arquivo `.env`, na raiz do projeto — a mesma fonte que `docker-compose.yml`
usa para interpolação. Não há duplicação: mude um valor de um jeito, ele
vale para os dois lados (CLI local e execução via Docker).

```bash
# Ver a configuração efetiva atual (arquivo persistido + env reais + padrões):
./sanitize config
# ou: pdf-sanitizer config   /  pdf-sanitizer config get   /  ./sanitize status

Pages: 300
Input limit: 500 MiB
Output limit: 3 GiB
RAM: 2 GiB
Timeout: 600 seconds
DPI: 150
Image format: jpeg
JPEG quality: 90
TMPFS: 2 GiB
Config file: /caminho/do/projeto/.env (not created yet -- using built-in defaults)
```

Definir um ou vários valores de uma vez (tudo validado **junto**, antes de
qualquer escrita — se algum valor for inválido, nada é gravado):

```bash
./sanitize config set \
  --max-pages 1000 \
  --max-input-size 500M \
  --max-output-size 3G \
  --memory 4G \
  --timeout 600 \
  --dpi 150 \
  --format jpeg \
  --jpeg-quality 90
```

Depois, sem editar mais nada:

```bash
./sanitize documento_grande.pdf -o documento_grande-sanitizado.pdf
```

Também é possível ajustar um valor isolado, no formato `<nome> <valor>`
(os mesmos nomes usados como `--flag`, sem o `--`):

```bash
./sanitize config set dpi 150
./sanitize config set memory 4G
```

Tamanhos aceitam sufixos legíveis (`500M`, `1G`, `3G`, `4G`; a CLI Python
também aceita frações, como `1.5G` — o wrapper Bash exige magnitude
inteira). Internamente tudo é normalizado para um número de bytes antes de
ser gravado, então o arquivo `.env` sempre guarda uma única forma canônica
por valor — ver `sizes.py`/`persistent_config.py`.

Para reverter tudo ao padrão recomendado:

```bash
./sanitize config reset
```

`config reset` remove o arquivo `.env` (em vez de reescrevê-lo com os
mesmos valores) — como todo valor padrão já É o recomendado, a simples
ausência do arquivo já resulta na configuração recomendada. Uma variável de
ambiente real, se definida no processo, nunca é apagada por `config
reset` (só o arquivo persistido é afetado).

Um exemplo de configuração recomendada para PDFs grandes (livros
escaneados, muitas páginas, DPI mais alto):

```bash
./sanitize config set \
  --max-pages 1000 \
  --max-input-size 500M \
  --max-output-size 3G \
  --memory 4G \
  --timeout 600 \
  --dpi 150 \
  --format jpeg \
  --jpeg-quality 90

./sanitize Guidorizzi-1.pdf -o Guidorizzi-1-L.pdf
```

Não existe um `.env` versionado no repositório — `.env.example` documenta
todas as chaves com os valores recomendados (copie para `.env` se preferir
editar à mão, embora o comando `config` já valide tudo por você); `.env`
em si é local e está no `.gitignore`, já que não guarda segredo nenhum,
apenas estado local de máquina.

### Segurança do arquivo de configuração

`config set` valida e normaliza todo valor antes de gravar (tamanhos,
inteiros, DPI, qualidade JPEG, timeout, número de páginas, formato de
imagem) — nenhum valor arbitrário chega ao `.env`, e nada aqui usa `eval`,
interpolação de shell insegura, ou construção de comando sem validação. O
arquivo é escrito de forma atômica (arquivo temporário + `rename`) com
permissões restritas ao dono (`0600`), então uma escrita interrompida nunca
deixa `.env`/`docker-compose.yml` num estado parcial.

---

## Logs

Logs estruturados em JSON (uma linha por evento), habilitados por padrão.
**Nunca** logam: conteúdo do PDF, o PDF em si, senhas, tokens, segredos, ou
o nome de arquivo bruto fornecido pelo usuário (só a versão sanitizada via
`security.sanitize_display_filename`, sem componentes de caminho).

Exemplo de linha de log (`processing_completed`):

```json
{"timestamp": "2026-09-09T10:15:03+0000", "level": "INFO", "logger": "pdf_sanitizer.sanitizer", "message": "processing_completed", "event": "processing_completed", "job_id": "a1b2c3d4e5f6...", "accepted": true, "original_pages": 3, "sanitized_pages": 3, "processing_time_seconds": 0.873, "domain_findings": 2}
```

Eventos emitidos: `upload_received`, `processing_started`,
`processing_completed`, `processing_failed`, `validation_rejected`,
`rejected_file_too_large`.

---

## Tratamento de erros

Nenhuma exceção interna (stack trace, caminho de arquivo, detalhe de
biblioteca) chega ao chamador — só `code` + `user_message` seguros
(ver `exceptions.py`). Na CLI, todo erro dessa tabela aparece como
`ERROR: <code>` seguido de uma linha com a mensagem, em `stderr`
(ver exemplos em [`sanitize`](#sanitize)).

| Situação | `code` / exceção | CLI |
|---|---|---|
| Não é PDF | `NotAPdfError` | exit 1 |
| PDF corrompido | `CorruptedPdfError` | exit 1 |
| Criptografado / senha necessária | `EncryptedPdfError` / `IncorrectPasswordError` | exit 1 |
| PDF sem páginas | `EmptyPdfError` | exit 1 |
| Entrada grande demais | `input_too_large` (`FileTooLargeError`) | exit 1 |
| Páginas demais | `TooManyPagesError` | exit 1 |
| Página grande demais | `PageTooLargeError` | exit 1 |
| Timeout | `ProcessingTimeoutError` | exit 1 |
| Sem memória | `OutOfMemoryError` | exit 1 |
| Falha ao renderizar | `RenderError` | exit 1 |
| Falha ao reconstruir | `ReconstructionError` | exit 1 |
| Worker morreu (ex.: OOM-killer do SO) | `WorkerCrashedError` | exit 1 |
| Saída sanitizada grande demais | `output_too_large` (`ValidationReport.rejection_code`, não é exceção) | exit 2 |
| Saída reprovou em outra checagem de validação | `sanitized_output_invalid` (`ValidationReport.rejection_code`, não é exceção) | exit 2 |
| Path traversal | `PathTraversalError` | — (não exposto à CLI; ver abaixo) |

Em qualquer erro crítico: o resultado parcial é descartado, os arquivos
temporários são removidos (`security.isolated_temp_dir` usa
`try/finally` + `shutil.rmtree`), o erro é logado internamente com detalhe,
e a resposta ao chamador é a versão segura acima.

Sobre *path traversal*: a CLI resolve caminhos literalmente, como qualquer
ferramenta de linha de comando que opera sobre arquivos locais do próprio
usuário — não há um "servidor" recebendo um caminho escolhido por outra
parte, então essa checagem não se aplica à entrada/saída informadas na
linha de comando. `security.assert_within_directory` continua em uso
internamente, para os diretórios de trabalho isolados por job (garantindo
que os arquivos temporários gerados durante o processamento nunca escrevam
fora do diretório isolado que lhes foi designado).

---

## Relatório de domínios

`inspect` combina achados estruturais (ações, anotações, JavaScript, anexos
— via `pikepdf`) com URLs de texto visível (via extração de texto do
`pypdfium2`), diferenciando a origem:

| `source_type` | Onde foi encontrado |
|---|---|
| `text` | Texto visível da página |
| `annotation_uri` | Ação `/URI` numa anotação (ex.: um link clicável) |
| `action_uri` | Ação `/URI` fora de uma anotação (ex.: `/OpenAction`) |
| `javascript` | URL encontrada dentro do texto de um script |
| `launch_action` | Ação `/Launch` (executa um arquivo/programa local) |
| `gotor_action` | Ação `/GoToR` ou `/GoToE` (referência remota/incorporada) |
| `submit_form_action` | Ação `/SubmitForm` |
| `embedded_file` | Presença de um anexo (via `pdf.attachments`) |

**Isto é diagnóstico, não uma garantia de segurança.** A extração de texto é
best-effort (regex sobre texto já extraído corretamente, não sobre bytes
crus — mas ainda assim heurística); a lista pode não ser exaustiva. A
remoção de todo o conteúdo interativo acontece de forma incondicional na
reconstrução, **independentemente** do que este relatório encontrou ou
deixou de encontrar.

---

## Exemplos de entrada e saída

**Entrada:** um PDF de 3 páginas com um link de texto, uma ação `/OpenAction`
que roda JavaScript, e um anexo executável escondido.

**Saída de `pdf-sanitizer inspect entrada.pdf --json`** (resumido):

```json
{
  "page_count": 3,
  "is_encrypted": false,
  "javascript_present": true,
  "open_action_present": true,
  "embedded_files_count": 1,
  "structural_scan": {
    "findings": [
      {"category": "OpenAction", "matched_token": "/OpenAction", "object_ref": "1 0 R", "context": "dictionary key /OpenAction present"},
      {"category": "JavaScript", "matched_token": "/JavaScript", "object_ref": "1 0 R", "context": "ActionSubtype == /JavaScript"}
    ],
    "objects_visited": 214,
    "truncated": false
  },
  "domain_report": {
    "findings": [
      {"source_type": "javascript", "domain": "malicious.example", "raw_value": "http://malicious.example/beacon", "page_index": null}
    ],
    "unique_domains": ["malicious.example"],
    "truncated": false
  }
}
```

**Saída de `pdf-sanitizer sanitize entrada.pdf -o saida.pdf --json-report relatorio.json`:**

```text
OK: wrote saida.pdf (59.77 KiB, 3 page(s), 1.02s).
1 domain/URL reference(s) were found in the original file and were removed. Run `pdf-sanitizer inspect entrada.pdf` for details.
```

`relatorio.json` contém o `SanitizationReport` completo, incluindo
`validation_report.checks` (todos `passed: true`), confirmando
estruturalmente que `saida.pdf` não tem `/JavaScript`, `/OpenAction`, nem
anexos.

### PNG × JPEG: redução de tamanho real

Medido neste projeto (`tests/test_size_optimization.py`) sobre uma página
de conteúdo denso, tipo foto (a 300×300px a 150 DPI, ruído por pixel —
justamente o tipo de conteúdo em que PNG (sem perdas) se sai pior e JPEG
(com perdas) se sai melhor; para páginas de texto/vetor puro a diferença é
bem menor, já que ambos os formatos comprimem regiões planas muito bem):

| Configuração | Tamanho do PDF final |
|---|---|
| PNG, 150 DPI | 1.77 MiB |
| JPEG qualidade 90, 150 DPI (**padrão**) | 431 KiB |
| JPEG qualidade 80, 150 DPI | 314 KiB |
| JPEG qualidade 90, 120 DPI | 308 KiB |

Nenhuma dessas variações muda o modelo de segurança — em todas, o PDF de
saída é reconstruído inteiramente a partir de páginas rasterizadas, sem
preservar nenhum objeto ativo do original.

---

## Checklist de segurança

- [x] PDF de entrada tratado como não confiável em todo o pipeline.
- [x] JavaScript existente no PDF nunca é executado (nenhuma dependência
      deste projeto possui motor de JS; nenhuma tentativa de "detectar e
      rodar" JS foi implementada, de propósito).
- [x] Processamento ocorre em subprocesso isolado (`spawn`), com timeout e
      RLIMIT — e, em produção, dentro do container descrito acima.
- [x] Dockerfile fornecido, multi-stage, sem compilador na imagem final.
- [x] `--network none` suportado e aplicado sempre — modo único de
      execução (local/lote), sem servidor HTTP e sem porta exposta.
- [x] Usuário não-root (uid/gid fixos 10001) no container.
- [x] Filesystem somente leitura (`--read-only` + tmpfs para escrita).
- [x] Sem acesso ao socket do Docker (nunca montado, em nenhum serviço).
- [x] `--cap-drop ALL`.
- [x] `--security-opt no-new-privileges`.
- [x] Limites de CPU e memória (Docker/Compose `cpus`, `mem_limit`) **e**
      dentro do processo (RLIMIT_AS/RLIMIT_CPU, melhor esforço).
- [x] Limite de tamanho de upload, aplicado por leitura em chunks (nunca
      buferiza mais que o limite antes de rejeitar).
- [x] Timeout de processamento (parede) via `security.run_isolated`,
      resultado sempre lido da fila **antes** de dar `join()` no processo
      filho — ver nota em [Testes](#testes) sobre o deadlock corrigido
      nesta revisão.
- [x] Diretórios temporários isolados por job (`tempfile.mkdtemp` sob um
      diretório dedicado, permissões `0700`).
- [x] Arquivos temporários apagados após o processamento
      (`try/finally` + `shutil.rmtree`, mesmo em caso de exceção).
- [x] Nenhum acesso a outros diretórios do host (a aplicação nunca lê/escreve
      fora do diretório temporário configurado e dos caminhos explicitamente
      passados pelo usuário na CLI).
- [x] Nenhum banco de dados.
- [x] Nenhuma leitura de credenciais/segredos.
- [x] Nenhuma variável de ambiente lida além das listadas em
      [Limites configuráveis](#limites-configuráveis) (via `pydantic-settings`
      com prefixo fixo `PDF_SANITIZER_`).
- [x] Configuração persistida (`.env`, `pdf-sanitizer config set`) validada e
      normalizada antes de qualquer escrita — sem `eval`, sem interpolação de
      shell insegura, sem construção de comando a partir de entrada não
      validada (ver [Segurança do arquivo de configuração](#segurança-do-arquivo-de-configuração)).
- [x] Reconstrução em vez de sanitização "in-place": o resultado é sempre
      um documento novo, montado só a partir de pixels renderizados —
      verdade tanto no modo PNG quanto no modo JPEG (padrão); nenhum dos
      dois preserva qualquer objeto ativo do PDF original.
- [x] Validação estrutural (não regex ingênuo) do resultado antes de liberar.
- [x] Path traversal: nomes de arquivo em disco sempre gerados
      internamente; nunca derivados de entrada externa.

---

## Testes

```bash
pip install -e ".[dev]"
pytest                       # suíte inteira (inclui testes de integração; alguns minutos)
pytest tests/test_security.py tests/test_validator.py tests/test_inspector.py  # subconjunto rápido
pytest --cov=pdf_sanitizer --cov-report=term-missing   # com cobertura
ruff check .
mypy
python scripts/security_check.py caminho/para/arquivo.pdf
```

`tests/test_sanitizer.py` e `tests/test_cli.py` disparam o pipeline
completo (cada caso gera um subprocesso real via `multiprocessing`), então
são mais lentos que os demais — isso é esperado e é o próprio mecanismo de
isolamento sendo exercitado, não overhead acidental.

> **Nota de transparência sobre esta revisão (JPEG + qualidade + DPI +
> limites/`config` persistidos):** a suíte completa foi de fato instalada
> e executada neste ambiente — `pytest` reporta **194 passed** (contra 81
> antes desta revisão; 113 testes novos, nenhum removido). `ruff check .`
> e `mypy` também rodaram nos arquivos tocados por esta revisão: os dois
> módulos novos (`sizes.py`, `persistent_config.py`) passam limpos nos
> dois; os dois `raise` novos em `security.py` foram ajustados para
> `raise ... from None` (`B904`); os `Optional[X]` novos em `models.py`/
> `config.py` seguem a convenção pré-existente de cada arquivo, não uma
> nova. `ruff`/`mypy` continuam reportando os mesmos avisos de estilo
> pré-existentes em módulos que esta revisão não alterou de forma
> substancial (`scanning.py`, o impressor de relatório de inspeção em
> `cli.py`) — fora do escopo desta mudança, e já sinalizados como tal na
> nota da revisão anterior logo abaixo.
>
> **Um bug real, pré-existente, foi encontrado e corrigido nesta revisão:**
> `security.run_isolated` chamava `process.join(timeout_seconds)` **antes**
> de ler o resultado da fila (`result_queue.get_nowait()`). `multiprocessing.Queue`
> é apoiada por um pipe do SO com buffer limitado (tipicamente 64 KiB no
> Linux); qualquer resultado maior que isso trava o processo filho (bloqueado
> escrevendo no pipe cheio) enquanto o processo pai está bloqueado em
> `join()` esperando o filho terminar — um *deadlock* clássico, resolvido só
> quando o timeout configurado expira e o pai mata o filho, transformando um
> `sanitize` bem-sucedido de qualquer PDF não trivial num
> `ProcessingTimeoutError` espúrio. Isso nunca apareceu na suíte de testes
> original porque todos os PDFs de teste produziam saídas pequenas o
> bastante para caber no buffer do pipe — só foi descoberto ao escrever
> `test_size_optimization.py` (item 17.1 do pedido), cujas páginas
> fotográficas de teste produzem PDFs grandes o suficiente para estourar o
> buffer. Corrigido lendo a fila **antes** de dar `join()` (padrão
> recomendado pela própria documentação do `multiprocessing`); ver o
> comentário em `security.run_isolated` e o teste de regressão
> `test_run_isolated_handles_a_result_larger_than_the_pipe_buffer` em
> `tests/test_security.py`. `pytest-timeout` (120s por teste) foi adicionado
> às dependências de desenvolvimento para que uma regressão futura desse
> tipo falhe alto em vez de travar silenciosamente o CI.

> **Nota de transparência sobre a revisão anterior (remoção da API/FastAPI):**
> a suíte completa foi de fato instalada e executada naquele ambiente —
> `pytest` reportou **81 passed**. Três fixtures em `tests/pdf_factory.py`
> (`pdf_empty_pages`, `pdf_corrupted`, `pdf_with_huge_page`) e uma asserção
> em `tests/test_inspector.py` (`test_not_a_pdf_raises`) precisaram de
> ajuste: seu comportamento dependia de detalhes de versão do
> `pikepdf`/`qpdf` instalado naquele ambiente (setembro de 2026) que
> divergiam do que a suíte original assumia — por exemplo, `qpdf` mais
> recente recusa abrir um PDF hand-rolled sem xref real em vez de
> "reparar" para zero páginas, e `pikepdf.add_blank_page()` passou a
> validar o mesmo limite de tamanho de página (3–14400 pt) que
> `renderer.py` já checava por conta própria. Nenhuma dessas correções
> tocou código de produção — só a construção dos PDFs de teste e uma
> expectativa de exceção equivocada; o mecanismo de segurança sendo
> testado em cada caso continua o mesmo. `ruff check .` também rodou limpo
> nos arquivos tocados por aquela revisão; reportava ~45 avisos de estilo
> pré-existentes (principalmente `Optional[X]` → `X | None`, sugestões do
> `SIM`/`B9xx`) em módulos que aquela revisão não alterou — não são erros,
> refletem só uma versão de `ruff` mais nova que o piso original do
> projeto, e ficavam fora do escopo daquela mudança (remover a API, não
> fazer lint sweep). Ver [Auditoria final](#auditoria-final).

---

## Limitações (leia isto)

Nenhum item abaixo é surpresa escondida — são as trocas inerentes à
abordagem escolhida.

1. **O parser/renderizador ainda processa o arquivo não confiável.**
   Renderizar uma página exige *analisar* o PDF original com um parser real
   (PDFium) e, antes disso, com pikepdf/qpdf para classificação. Uma
   vulnerabilidade de memória em qualquer um dos dois poderia, em teoria,
   ser acionada por uma página maliciosa **antes** que a sanitização tenha
   qualquer chance de ajudar. É exatamente por isso que esse processamento
   roda isolado (subprocesso com timeout/RLIMIT, e em produção dentro do
   container descrito acima) — para **limitar o raio de impacto** de uma
   falha desse tipo, não para impedi-la. "Remover o JavaScript" não é
   sinônimo de "PDF seguro": o próprio ato de abrir o arquivo já é a maior
   superfície de risco, e é isso que o isolamento existe para conter.
2. **O resultado é rasterizado — não é mais um PDF de texto.** O documento
   final não tem texto selecionável/pesquisável, não é acessível a leitores
   de tela, e qualquer formulário preenchido é "achatado" em pixels
   estáticos. Isso é uma troca deliberada (fidelidade/usabilidade por
   segurança, conforme pedido explicitamente), mas é uma limitação de uso
   real, não cosmética.
3. **Arquivos tendem a ficar maiores** que o PDF vetorial original mesmo com
   JPEG, para PDFs originalmente compostos majoritariamente por texto
   vetorial simples — texto vetorial comprime de forma extraordinária,
   melhor que qualquer rasterização. Dito isso, `PDF_SANITIZER_OUTPUT_IMAGE_FORMAT=jpeg`
   (o padrão) já reduz bastante o tamanho frente ao PNG anterior,
   especialmente para páginas fotográficas/escaneadas (ver [PNG × JPEG:
   redução de tamanho real](#png--jpeg-redução-de-tamanho-real)); ajuste
   `PDF_SANITIZER_JPEG_QUALITY` e `PDF_SANITIZER_RENDER_DPI` para equilibrar
   fidelidade visual e tamanho. JPEG introduz perdas *além* da própria
   rasterização (artefatos de blocos, subamostragem de crominância) — para
   documentos onde isso importa (texto muito pequeno, line art fina),
   `PDF_SANITIZER_OUTPUT_IMAGE_FORMAT=png` continua disponível, sem perdas
   adicionais.
4. **Metadados são perdidos por completo** (título, autor, palavras-chave,
   XMP, ...) — de novo, uma troca deliberada (superfície mínima), mas some
   informação que às vezes é desejável manter.
5. **O relatório de domínios é melhor-esforço**, não exaustivo — ver a seção
   dedicada acima. Nunca trate "zero domínios encontrados" como "arquivo
   seguro".
6. **Evite `--password` em scripts/terminal compartilhado.** A CLI aceita a
   senha de um PDF criptografado via `--password` (visível em `ps`/histórico
   do shell) ou `--password-stdin` (não fica em nenhum dos dois) — prefira
   sempre a segunda forma. Isto é uma limitação de qualquer CLI que aceita
   segredos como argumento, não específica deste projeto.
7. **Concordância entre parsers não é infalível.** Quando pikepdf aceita um
   arquivo mas o PDFium falha ao renderizar uma página específica (ou
   vice-versa), isso é reportado como erro de renderização — é uma
   divergência real entre duas implementações complexas, e pode
   ocasionalmente rejeitar um PDF legítimo mas incomum.
8. **RLIMIT_AS/RLIMIT_CPU são melhor-esforço e específicos de POSIX** — não
   funcionam no Windows, e não são uma sandbox de verdade (não impedem
   acesso a disco/rede por si só; o container é quem faz isso).
9. **O isolamento por `spawn` adiciona latência** (centenas de milissegundos
   por job, tipicamente) — o preço de um processo novo, não reaproveitado,
   por sanitização. É uma troca deliberada por isolamento mais forte que
   `fork` (que herdaria memória/descritores do processo pai).
10. **Nenhum teste de fuzzing foi executado** como parte deste entregável.
    Para uso em produção com volume alto ou dados sensíveis, complementar
    com fuzzing direcionado às bibliotecas de parsing (ex.: `atheris`,
    corpora de PDFs malformados conhecidos) é recomendado.
11. **Este projeto não foi auditado por terceiros.** É uma implementação
    defensiva e documentada, não uma certificação de segurança.

---

## Auditoria final

Revisão original feita item a item conforme solicitado na época (quando o
projeto ainda incluía a API HTTP); depois atualizada para remover as
referências a FastAPI/Starlette e ao modo API. Esta revisão (JPEG +
qualidade + DPI + limites/`config` persistidos) reverificou os itens
abaixo mais uma vez, com destaque para "Problemas de concorrência" (linha
atualizada) — ver a nota de transparência em [Testes](#testes) para o
detalhe completo, incluindo o deadlock encontrado e corrigido.

| Item revisado | Resultado |
|---|---|
| Imports incorretos | Toda API de terceiros usada (`pikepdf.open`/`Pdf.new`/`.objects`/`.attachments`/`NameTree`/`AttachedFileSpec`/`PasswordError`; `pypdfium2.PdfDocument`/`.render`/`.get_textpage`; `img2pdf.convert`) foi conferida contra documentação e exemplos oficiais atuais (buscas na web, set/2026) antes de ser usada — não foi escrita de memória sem checagem. |
| APIs inexistentes | Nenhuma função/parâmetro foi inventado; onde a certeza era menor (ex.: parâmetros exatos de `PdfPage.render()`), optou-se por usar apenas a forma documentada e confirmada (`page.render(scale=...)`), evitando parâmetros não verificados. |
| Argumentos incompatíveis | Assinaturas de função conferidas nos pontos de maior risco (ex.: `pikepdf.open()` espera stream/caminho, não `bytes` crus — corrigido explicitamente com `io.BytesIO`; `pypdfium2.PdfDocument` aceita `bytes` diretamente — confirmado antes de usar). |
| Caminhos inseguros | Nenhum caminho de disco é derivado de entrada externa; nomes de arquivo em disco são sempre `uuid4().hex` (`security.secure_random_filename`); `security.assert_within_directory` disponível e testado para qualquer futuro uso que precise resolver caminhos relativos a uma base. |
| Problemas de concorrência | Cada job roda em processo próprio (`multiprocessing`, `spawn`) sem estado compartilhado mutável entre pai e filho além da fila de resultado; `Settings` é imutável (`frozen=True`) para evitar mutação compartilhada acidental. **Esta revisão encontrou e corrigiu um deadlock real e pré-existente**: `run_isolated` chamava `process.join(timeout_seconds)` antes de drenar `result_queue`, travando pai e filho sempre que o resultado excedesse o buffer do pipe do SO (tipicamente 64 KiB) — invisível na suíte original porque nenhum PDF de teste produzia uma saída tão grande; agora corrigido lendo a fila antes de dar `join()`, com teste de regressão dedicado (ver nota em [Testes](#testes)). Concorrência entre múltiplos usuários não se aplica: esta é uma ferramenta local/lote, de um usuário por vez. |
| Arquivos temporários não removidos | `security.isolated_temp_dir` usa `try/finally` com `shutil.rmtree(..., ignore_errors=True)`; testado explicitamente em `test_security.py` (remoção tanto no caminho de sucesso quanto após exceção). |
| Exceções não tratadas | Toda função do worker isolado tem uma rede de segurança (`security._child_entrypoint` captura `PdfSanitizerError`, `MemoryError`, e `BaseException` genérico) — o processo pai nunca recebe uma exceção não serializável, e a CLI nunca deixa vazar um traceback bruto ao usuário. |
| Configurações inseguras | Nenhum segredo/credencial hardcoded; toda configuração vem de variáveis de ambiente com prefixo fixo, do arquivo `.env` persistido (validado/normalizado por `config set` antes de qualquer escrita — sem `eval`, sem interpolação de shell) ou de um valor padrão conservador — nunca "ilimitado". |
| Dependências incompatíveis | Faixas de versão (`>=X,<Y`) escolhidas para permitir patches de segurança automáticos sem quebrar a API usada; nenhuma dependência transitiva de risco conhecido foi identificada na pesquisa feita; nenhuma dependência nova foi adicionada nesta revisão além de `pytest-timeout` (apenas desenvolvimento/CI, não roda em produção). |
| Problemas no Docker | Build multi-stage conferido linha a linha; usuário não-root com uid/gid fixos; sem `EXPOSE` em lugar nenhum da imagem (não há servidor HTTP); `docker-compose.yml` tem um único serviço, de execução local/lote, e pode usar `network_mode: none` incondicionalmente. Limites antes hardcoded (`mem_limit`, `tmpfs size=`) agora vêm de `${VAR:-default}`, com o *default* de cada um idêntico ao valor anterior/ao padrão de `Settings` — comportamento de um checkout novo, sem `.env`, é idêntico ao de antes desta revisão. |
| Funcionalidades que possam executar JavaScript do PDF | Nenhuma dependência usada possui motor de JavaScript; nenhuma tentativa de "detectar e avaliar" JS foi implementada, por decisão explícita (ver `sanitizer.py`, módulo de renderização) — verdade nos dois formatos de saída (PNG e JPEG, ambos rasterizados da mesma forma antes de `img2pdf.convert()`). |
| Possibilidade de acesso à rede | Nenhuma chamada de rede em qualquer módulo do pacote; `--network none` se aplica sempre, sem exceção. |
| Path traversal | Coberto por `assert_within_directory` + testes dedicados, para os diretórios de trabalho isolados por job; a CLI resolve caminhos de entrada/saída literalmente, como qualquer ferramenta de linha de comando sobre arquivos locais do próprio usuário. |
| Vazamento de informações | Exceções nunca expõem `message` (interno) ao chamador, só `user_message`; logs nunca incluem conteúdo do PDF, segredos, ou caminhos brutos; relatório de domínios truncado a um teto configurável para evitar saídas desproporcionalmente grandes; PDF reconstruído tem metadados mínimos e sem timestamp (`img2pdf.convert(..., nodate=True)`), tanto em PNG quanto em JPEG. |

**Limitações que permanecem após esta revisão** (resumo — ver a seção
[Limitações](#limitações-leia-isto) para o detalhe completo): o
parser/renderizador subjacente continua sendo uma superfície de ataque
real, mitigada por isolamento e não eliminada; o relatório de domínios é
melhor-esforço; JPEG (o novo padrão) introduz perdas além da própria
rasterização, mitigável trocando para PNG ou ajustando qualidade/DPI;
nenhuma auditoria de terceiros ou fuzzing foi realizada. A suíte de testes
**foi** executada nesta revisão e na anterior (194 passed nesta revisão,
81 na anterior — ver [Testes](#testes) para o detalhe completo, incluindo
o deadlock de concorrência encontrado e corrigido). Nenhuma alegação de
"zero erros" ou "segurança absoluta" é feita — o objetivo deste projeto é
uma implementação defensiva, documentada e auditável, não uma garantia.

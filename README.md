# pdf-sanitizer

Ferramenta local para reduzir os riscos associados a PDFs não confiáveis. Cada página do documento original é renderizada como imagem e, em seguida, um novo PDF é reconstruído a partir dessas imagens. A estrutura interativa do arquivo original — como JavaScript, ações, formulários e anexos — não é reaproveitada.

O projeto oferece uma interface de linha de comando (CLI) e processamento em lote com Docker. Não disponibiliza servidor HTTP, API de rede ou portas expostas.

> **Aviso de segurança:** esta ferramenta reduz a superfície de risco, mas não garante que um PDF seja seguro. O próprio processamento do arquivo exige parsers e renderizadores, que também podem conter vulnerabilidades. Para processar documentos não confiáveis, prefira a execução isolada com Docker.

## Funcionalidades

- Reconstrução de PDFs a partir de páginas rasterizadas.
- Inspeção estrutural do PDF original, incluindo ações, JavaScript e anexos.
- Relatório de URLs e domínios encontrados no documento.
- Validação estrutural do PDF reconstruído antes de liberar o resultado.
- Processamento isolado em subprocesso, com timeout e limites de recursos.
- Execução em container Docker sem rede, com usuário não-root e filesystem somente leitura.
- Configuração de DPI, formato de imagem (JPEG ou PNG), qualidade JPEG e limites de processamento.

## Requisitos

- Python 3.11 ou superior para instalação local.
- Docker e Docker Compose v2 para execução isolada pelo wrapper `./sanitize`.

## Instalação local

```bash
python -m venv .venv
source .venv/bin/activate

# Instalação da ferramenta
pip install -e .

# Dependências adicionais para desenvolvimento e testes
pip install -e ".[dev]"
```

Verifique a instalação:

```bash
pdf-sanitizer version
```

## Uso

### Sanitizar um PDF

```bash
pdf-sanitizer sanitize entrada.pdf -o saida.pdf
```

Também é possível usar o módulo diretamente:

```bash
python -m pdf_sanitizer sanitize entrada.pdf -o saida.pdf
```

### Inspecionar um PDF

O comando `inspect` gera um relatório somente leitura sobre a estrutura do arquivo original:

```bash
pdf-sanitizer inspect entrada.pdf
```

Para obter saída JSON:

```bash
pdf-sanitizer inspect entrada.pdf --json
```

### Validar um PDF

```bash
pdf-sanitizer validate saida.pdf
```

### Outros comandos

```bash
pdf-sanitizer config   # exibe a configuração efetiva
pdf-sanitizer status   # exibe o estado da configuração
pdf-sanitizer version  # exibe as versões
```

## Execução isolada com Docker

Para processar PDFs não confiáveis, use o wrapper `./sanitize`. Ele executa a sanitização dentro do container isolado.

Construa a imagem:

```bash
docker compose build
```

Sanitize um arquivo:

```bash
./sanitize entrada.pdf
```

Por padrão, o arquivo de saída recebe o sufixo `-sanitizado`. Para definir outro caminho:

```bash
./sanitize entrada.pdf -o saida.pdf
```

O container aplica isolamento de rede (`network_mode: none`), usuário não-root, filesystem somente leitura, remoção de capabilities e limites de CPU e memória.

## Configuração

A configuração pode ser consultada e alterada pelo wrapper, sem editar os arquivos do projeto:

```bash
./sanitize config
./sanitize config set --dpi 200 --format jpeg --jpeg-quality 85
./sanitize config reset
```

Principais padrões:

| Opção | Padrão |
|---|---:|
| Tamanho máximo de entrada | 500 MiB |
| Número máximo de páginas | 300 |
| DPI de renderização | 150 |
| Formato de imagem | JPEG |
| Qualidade JPEG | 90 |
| Tamanho máximo de saída | 3 GiB |
| Timeout de processamento | 600 segundos |
| Memória máxima por execução | 2 GiB |

As configurações persistidas ficam em `.env`. Esse arquivo é local e não deve ser versionado; use `.env.example` como referência.

## Testes

Instale as dependências de desenvolvimento e execute:

```bash
pip install -e ".[dev]"
pytest
ruff check .
mypy
```

Verificação de segurança de um PDF:

```bash
python scripts/security_check.py caminho/para/arquivo.pdf
```

## Limitações

- O PDF de saída é rasterizado: o texto deixa de ser selecionável ou pesquisável, e formulários são convertidos em imagem.
- Metadados do documento original, como título e autor, não são preservados.
- JPEG é o formato padrão e introduz perda de qualidade. Use PNG quando precisar de uma saída sem perdas adicionais de compressão.
- O relatório de domínios é de melhor esforço e pode não identificar todas as referências.
- O parser e o renderizador ainda precisam processar o PDF original; o isolamento reduz o impacto potencial de falhas, mas não elimina essa superfície de ataque.
- O projeto não substitui uma auditoria de segurança independente. Não foi realizado fuzzing como parte do desenvolvimento descrito na documentação original.
# Política de Segurança

## Visão geral

Este projeto sanitiza arquivos PDF não confiáveis renderizando cada página como imagem e reconstruindo um novo PDF a partir dessas imagens, removendo JavaScript, ações automáticas, anexos, formulários interativos e outros objetos ativos. Por lidar diretamente com conteúdo potencialmente malicioso, falhas de segurança neste projeto podem ter impacto direto na segurança de quem o utiliza — reportar vulnerabilidades de forma responsável é especialmente importante aqui.

## Versões suportadas

Este projeto ainda não mantém múltiplas linhas de lançamento paralelas (branches de LTS, backports, etc.). Correções de segurança são aplicadas apenas à versão mais recente disponível. Antes de reportar um problema, atualize para a última versão e confirme se ele persiste (pdf-sanitizer version mostra a versão instalada e das principais dependências).

## Como reportar uma vulnerabilidade

*Não abra uma Issue pública, Discussion ou Pull Request descrevendo a vulnerabilidade.* Divulgar publicamente uma falha de segurança antes de existir uma correção expõe todos os usuários do projeto a risco desnecessário.

Em vez disso, utilize o recurso de *Private Vulnerability Reporting* do GitHub neste repositório:

1. Acesse a aba *Security* do repositório.
2. Clique em *"Report a vulnerability"*.
3. Descreva o problema seguindo as orientações da seção abaixo.

Esse canal notifica os mantenedores de forma privada, sem tornar os detalhes públicos, e permite, quando aplicável, a criação de um Security Advisory e a solicitação de um CVE diretamente pelo GitHub.

Se o recurso de Private Vulnerability Reporting não estiver disponível no momento do seu acesso, evite qualquer canal público (issues, redes sociais, fóruns) até que um meio privado possa ser utilizado.

## O que incluir no relatório

Para agilizar a análise, inclua o máximo possível de:

- Versão do projeto afetada (saída de pdf-sanitizer version, incluindo as versões de pikepdf, pypdfium2, img2pdf e Pillow listadas).
- Forma de execução utilizada: CLI instalada via pip, via Docker/docker-compose.yml, ou pelo wrapper ./sanitize.
- Passos detalhados para reproduzir o problema.
- Comportamento esperado vs. comportamento observado.
- Sistema operacional, versão do Python e, se aplicável, versão do Docker/Docker Compose.
- Logs relevantes.
- Se possível, um PDF de exemplo mínimo que reproduza o problema.

### Aviso importante sobre os PDFs enviados

*Não envie PDFs que contenham dados pessoais, confidenciais, sigilosos ou de terceiros* ao relatar uma vulnerabilidade. Se um arquivo for necessário para reproduzir o problema, construa (ou reduza) um PDF mínimo e sintético, contendo apenas o necessário para demonstrar a falha. Trate qualquer PDF anexado a um relatório como um artefato que outras pessoas poderão ver.

## Limitações de segurança conhecidas

Este projeto foi desenhado com segurança como prioridade, mas não oferece garantia absoluta de que qualquer PDF de saída esteja livre de risco. Em particular:

- A rasterização (renderizar cada página como imagem e reconstruir um PDF novo) é a principal fronteira de segurança, mas depende de bibliotecas de terceiros para interpretar o PDF original (pikepdf, PDFium via pypdfium2) e para gerar a saída (img2pdf, Pillow). Essas bibliotecas continuam sendo uma superfície de ataque real — bugs de parsing, corrupção de memória ou outras vulnerabilidades nelas podem afetar este projeto mesmo com a arquitetura de sanitização correta.
- Isolamento de processo, limites de tempo/memória/tamanho e ausência de acesso à rede reduzem o impacto de uma eventual falha nessas bibliotecas, mas não a eliminam.
- O relatório de domínios/URLs extraídos do PDF original é melhor-esforço e não deve ser tratado como uma lista exaustiva de todo conteúdo suspeito presente no arquivo original.
- Nenhuma auditoria de segurança de terceiros nem campanha formal de fuzzing foi realizada sobre este projeto até o momento.

Reportar uma vulnerabilidade não implica reconhecimento de que o projeto é ou deveria ser "totalmente seguro" — o objetivo é uma implementação defensiva, documentada e auditável, não uma garantia absoluta.

## Recomendações para quem usa este projeto

- Mantenha o projeto atualizado para a versão mais recente.
- Mantenha as dependências Python declaradas em pyproject.toml (pikepdf, pypdfium2, img2pdf, Pillow, pydantic, pydantic-settings, typer, entre outras) atualizadas dentro das faixas de versão suportadas, para receber correções de segurança upstream.
- Ao usar a imagem Docker (Dockerfile/docker-compose.yml), reconstrua-a periodicamente para incorporar atualizações do sistema operacional base e das dependências.
- Trate qualquer PDF de entrada como não confiável, mesmo após sanitizado, ao decidir onde e como reabri-lo.

## Escopo

Vulnerabilidades no código deste projeto (pipeline de sanitização, CLI, empacotamento Docker, arquivo de configuração persistido) estão no escopo deste processo de divulgação. Vulnerabilidades encontradas em dependências de terceiros (por exemplo, no próprio PDFium, pikepdf ou img2pdf) devem, idealmente, também ser reportadas diretamente ao projeto correspondente — um relatório aqui sobre esse tipo de problema ainda é bem-vindo.

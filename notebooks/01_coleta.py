# Databricks notebook source
# MAGIC %md
# MAGIC # 01 · Coleta
# MAGIC
# MAGIC Persiste os arquivos brutos no Volume do Unity Catalog (`/Volumes/workspace/mvp_vuln/brutos`).
# MAGIC
# MAGIC **Modo `repositorio` (padrão, reprodutível):** copia os arquivos versionados em `dados/brutos/`
# MAGIC do repositório GitHub (clonado no Databricks como *Git folder*) para o Volume. Assim o pipeline
# MAGIC roda sobre exatamente o mesmo retrato dos dados usado na análise do README.
# MAGIC
# MAGIC **Modo `fontes`:** baixa os arquivos diretamente das fontes oficiais (útil para atualizar o MVP).
# MAGIC O NVD não é baixado aqui: a coleta via API leva ~20 minutos e é feita pelo script
# MAGIC `scripts/coleta_nvd.py`.
# MAGIC
# MAGIC | Arquivo | Fonte | Licença |
# MAGIC |---|---|---|
# MAGIC | `kev.json` | CISA — Known Exploited Vulnerabilities Catalog | CC0 1.0 (domínio público) |
# MAGIC | `nvd_cves.ndjson.gz` | NIST — National Vulnerability Database, API CVE 2.0 | Domínio público (governo dos EUA) |
# MAGIC | `epss_scores-current.csv.gz` | FIRST — Exploit Prediction Scoring System | Uso livre, com atribuição |
# MAGIC | `epss_scores-2025-01-01.csv.gz` | FIRST — EPSS, retrato histórico | Uso livre, com atribuição |
# MAGIC | `cwe_1000.csv.zip` | MITRE — Common Weakness Enumeration, visão 1000 | Termos de uso da MITRE (uso livre) |

# COMMAND ----------

# MAGIC %run ./00_configuracao

# COMMAND ----------

dbutils.widgets.dropdown("modo", "repositorio", ["repositorio", "fontes"], "Origem dos arquivos")
modo = dbutils.widgets.get("modo")

# COMMAND ----------

import os
import shutil
import urllib.request
from datetime import datetime, timezone

URLS = {
    "kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "epss_atual": "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
    "epss_corte": "https://epss.empiricalsecurity.com/epss_scores-2025-01-01.csv.gz",
    "cwe": "https://cwe.mitre.org/data/csv/1000.csv.zip",
}

# Pasta dados/brutos do Git folder: sobe dois níveis a partir deste notebook
caminho_notebook = dbutils.notebook.entry_point.getDbutils().notebook().getContext().notebookPath().get()
pasta_repo = "/Workspace" + os.path.dirname(os.path.dirname(caminho_notebook))
pasta_dados_repo = f"{pasta_repo}/dados/brutos"

registros = []
for chave, arquivo in ARQUIVOS.items():
    destino = caminho(chave)
    if modo == "fontes" and chave in URLS:
        urllib.request.urlretrieve(URLS[chave], destino)
        origem = URLS[chave]
    else:
        origem = f"{pasta_dados_repo}/{arquivo}"
        shutil.copyfile(origem, destino)
    registros.append((arquivo, origem, os.path.getsize(destino), datetime.now(timezone.utc)))
    print(f"{arquivo:32s} {os.path.getsize(destino)/1e6:8.2f} MB  <- {origem}")

# COMMAND ----------

# MAGIC %md
# MAGIC Registro da coleta (linhagem): cada execução acrescenta uma linha por arquivo.

# COMMAND ----------

log = spark.createDataFrame(registros, "arquivo string, origem string, tamanho_bytes long, copiado_em timestamp")
log.write.mode("append").saveAsTable("bronze_log_coleta")
display(spark.table("bronze_log_coleta").orderBy("copiado_em", ascending=False))

# COMMAND ----------

display(dbutils.fs.ls(CAMINHO_VOLUME))

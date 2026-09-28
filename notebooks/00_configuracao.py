# Databricks notebook source
# MAGIC %md
# MAGIC # 00 · Configuração
# MAGIC
# MAGIC Parâmetros compartilhados por todos os notebooks do pipeline. Os demais notebooks
# MAGIC executam este com `%run ./00_configuracao`.
# MAGIC
# MAGIC | Objeto | Nome |
# MAGIC |---|---|
# MAGIC | Catálogo (Unity Catalog) | `workspace` (padrão do Databricks Free Edition) |
# MAGIC | Esquema | `mvp_vuln` |
# MAGIC | Volume com os arquivos brutos | `/Volumes/workspace/mvp_vuln/brutos` |
# MAGIC
# MAGIC Camadas (arquitetura medalhão): tabelas `bronze_*` (dado bruto), `prata_*` (limpo e tipado)
# MAGIC e `dim_*` / `fato_*` (camada ouro, modelo dimensional).

# COMMAND ----------

CATALOGO = "workspace"
ESQUEMA = "mvp_vuln"
VOLUME = "brutos"
CAMINHO_VOLUME = f"/Volumes/{CATALOGO}/{ESQUEMA}/{VOLUME}"

# Recorte da população analisada: CVEs publicadas no NVD de 2021 a 2025
INICIO_POPULACAO = "2021-01-01"
FIM_POPULACAO = "2025-12-31"

# Data de corte do teste prospectivo (pergunta P3)
DATA_CORTE = "2025-01-01"

ARQUIVOS = {
    "kev": "kev.json",
    "nvd": "nvd_cves.ndjson.gz",
    "epss_atual": "epss_scores-current.csv.gz",
    "epss_corte": "epss_scores-2025-01-01.csv.gz",
    "cwe": "cwe_1000.csv.zip",
}

spark.sql(f"CREATE SCHEMA IF NOT EXISTS {CATALOGO}.{ESQUEMA}")
spark.sql(f"CREATE VOLUME IF NOT EXISTS {CATALOGO}.{ESQUEMA}.{VOLUME}")
spark.sql(f"USE {CATALOGO}.{ESQUEMA}")

def caminho(chave):
    return f"{CAMINHO_VOLUME}/{ARQUIVOS[chave]}"

print(f"Usando {CATALOGO}.{ESQUEMA}; arquivos brutos em {CAMINHO_VOLUME}")

# Databricks notebook source
# MAGIC %md
# MAGIC # 02 · Camada bronze
# MAGIC
# MAGIC Lê os arquivos do Volume e grava tabelas Delta **sem alterar o conteúdo**: apenas
# MAGIC achata a estrutura (quando necessário) e acrescenta colunas de linhagem
# MAGIC (`_arquivo_origem`, `_carregado_em`). Toda regra de negócio fica na camada prata.

# COMMAND ----------

# MAGIC %run ./00_configuracao

# COMMAND ----------

import gzip
import pandas as pd
from pyspark.sql import functions as F

def com_linhagem(df, chave):
    return (df.withColumn("_arquivo_origem", F.lit(ARQUIVOS[chave]))
              .withColumn("_carregado_em", F.current_timestamp()))

def gravar(df, tabela):
    df.write.mode("overwrite").option("overwriteSchema", "true").saveAsTable(tabela)
    print(f"{tabela:24s} {spark.table(tabela).count():>9,d} linhas")

# COMMAND ----------

# MAGIC %md
# MAGIC ### KEV (CISA)
# MAGIC JSON com um cabeçalho (versão do catálogo) e a lista `vulnerabilities`, que é explodida em linhas.

# COMMAND ----------

kev_bruto = spark.read.option("multiLine", True).json(caminho("kev"))
bronze_kev = (kev_bruto
    .select("catalogVersion", "dateReleased", F.explode("vulnerabilities").alias("v"))
    .select("catalogVersion", "dateReleased", "v.*"))
gravar(com_linhagem(bronze_kev, "kev"), "bronze_kev")

# COMMAND ----------

# MAGIC %md
# MAGIC ### NVD (NIST)
# MAGIC NDJSON gerado por `scripts/coleta_nvd.py`, uma CVE por linha. O esquema é declarado
# MAGIC explicitamente para evitar inferência de tipos divergente entre execuções.

# COMMAND ----------

esquema_nvd = """
    cve_id string, publicado_em string, modificado_em string, status_nvd string, cwes array<string>,
    cvss_versao string, cvss_fonte string, cvss_score double, cvss_severidade string,
    cvss_vetor_ataque string, cvss_complexidade string, cvss_privilegios string, cvss_interacao string,
    cvss_explorabilidade double, cvss_impacto double
"""
bronze_nvd = spark.read.schema(esquema_nvd).json(caminho("nvd"))
gravar(com_linhagem(bronze_nvd, "nvd"), "bronze_nvd")

# COMMAND ----------

# MAGIC %md
# MAGIC ### EPSS (FIRST)
# MAGIC CSV compactado cuja primeira linha é um comentário com a versão do modelo e a data do score.
# MAGIC Esses metadados são lidos à parte e gravados como colunas.

# COMMAND ----------

def ler_epss(chave):
    with gzip.open(caminho(chave), "rt", encoding="utf-8") as f:
        meta = dict(item.split(":", 1) for item in f.readline().strip().lstrip("#").split(","))
    df = spark.read.option("header", True).option("comment", "#").csv(caminho(chave))
    return (df.withColumn("versao_modelo", F.lit(meta["model_version"]))
              .withColumn("data_score", F.lit(meta["score_date"][:10])))

gravar(com_linhagem(ler_epss("epss_atual"), "epss_atual"), "bronze_epss_atual")
gravar(com_linhagem(ler_epss("epss_corte"), "epss_corte"), "bronze_epss_corte")

# COMMAND ----------

# MAGIC %md
# MAGIC ### CWE (MITRE)
# MAGIC O Spark não lê `.zip` diretamente; o arquivo é lido com pandas e convertido.

# COMMAND ----------

cwe_pd = pd.read_csv(caminho("cwe"), index_col=False, dtype=str)[["CWE-ID", "Name", "Weakness Abstraction", "Status"]]
cwe_pd.columns = ["cwe_numero", "nome", "abstracao", "status"]
cwe_pd = cwe_pd.astype(object).where(cwe_pd.notna(), None)  # NaN do pandas -> NULL no Spark
cwe_df = spark.createDataFrame(cwe_pd, "cwe_numero string, nome string, abstracao string, status string")
gravar(com_linhagem(cwe_df, "cwe"), "bronze_cwe")

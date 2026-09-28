# Databricks notebook source
# MAGIC %md
# MAGIC # 03 · Camada prata — limpeza e regras de negócio
# MAGIC
# MAGIC Todas as regras que afetam a interpretação dos resultados estão listadas aqui e
# MAGIC replicadas em `scripts/pipeline_local.py`.
# MAGIC
# MAGIC | # | Regra | Motivo |
# MAGIC |---|---|---|
# MAGIC | R1 | `cve_id` padronizado: sem espaços e em maiúsculas | Chave de junção entre as três fontes |
# MAGIC | R2 | NVD: deduplicação por `cve_id`, mantendo o registro com `modificado_em` mais recente | A coleta por janelas pode repetir CVEs republicadas |
# MAGIC | R3 | NVD: CVEs com status `Rejected` são excluídas | CVE rejeitada não é vulnerabilidade válida |
# MAGIC | R4 | CVSS: usa v3.1 (ou v3.0 se não houver), priorizando a nota *Primary* do NVD sobre a do fabricante (CNA) | Uniformidade: uma única escala e um único avaliador sempre que possível |
# MAGIC | R5 | `cvss_score` fora de [0, 10] vira nulo; faixa qualitativa recalculada pela tabela oficial do CVSS v3 | Conformidade com o domínio |
# MAGIC | R6 | CVE sem métrica CVSS v3 recebe faixa `Sem CVSS` (não é descartada) | Descartá-las esconderia exatamente o ponto cego de uma política baseada em CVSS |
# MAGIC | R7 | CWE principal = primeira CWE específica (`CWE-n`); na falta, a genérica do NVD (`NVD-CWE-Other`/`noinfo`); na falta, `SEM-CWE` | Uma CWE por CVE para o modelo estrela |
# MAGIC | R8 | KEV: `knownRansomwareCampaignUse = 'Known'` → `true`; `Unknown` → `false` | "Unknown" significa "sem evidência pública", não "não usado" — ressalva registrada no catálogo |
# MAGIC | R9 | EPSS: `epss` e `percentile` convertidos para `double`; uma linha por CVE | Tipagem |

# COMMAND ----------

# MAGIC %run ./00_configuracao

# COMMAND ----------

from pyspark.sql import functions as F
from pyspark.sql.window import Window

def gravar(df, tabela):
    df.write.mode("overwrite").option("overwriteSchema", "true").saveAsTable(tabela)
    print(f"{tabela:24s} {spark.table(tabela).count():>9,d} linhas")

def padronizar_cve(col):  # R1
    return F.upper(F.trim(col))

def cwe_principal(col_lista):  # R7
    especificas = F.filter(col_lista, lambda c: c.rlike("^CWE-[0-9]+$"))
    return F.coalesce(F.try_element_at(especificas, F.lit(1)),
                      F.try_element_at(col_lista, F.lit(1)),
                      F.lit("SEM-CWE"))

def faixa_cvss(col):  # R5 / R6
    return (F.when(col.isNull(), "Sem CVSS")
             .when(col == 0, "Nenhuma")
             .when(col < 4, "Baixa")
             .when(col < 7, "Média")
             .when(col < 9, "Alta")
             .otherwise("Crítica"))

# COMMAND ----------

# MAGIC %md
# MAGIC ### prata_nvd

# COMMAND ----------

janela = Window.partitionBy("cve_id").orderBy(F.col("modificado_em").desc())
nvd = (spark.table("bronze_nvd")
    .withColumn("cve_id", padronizar_cve(F.col("cve_id")))
    .withColumn("modificado_em", F.to_timestamp("modificado_em"))
    .withColumn("_ordem", F.row_number().over(janela))
    .filter("_ordem = 1").drop("_ordem")                                   # R2
    .filter(F.col("status_nvd") != "Rejected")                             # R3
    .withColumn("data_publicacao", F.to_date(F.to_timestamp("publicado_em")))
    .withColumn("cvss_score", F.when(F.col("cvss_score").between(0, 10), F.col("cvss_score")))  # R5
    .withColumn("faixa_cvss", faixa_cvss(F.col("cvss_score")))
    .withColumn("cwe_principal", cwe_principal(F.coalesce("cwes", F.array().cast("array<string>"))))
    .fillna("N/D", ["cvss_vetor_ataque", "cvss_complexidade", "cvss_privilegios", "cvss_interacao"])
    .drop("publicado_em", "_arquivo_origem", "_carregado_em"))
gravar(nvd, "prata_nvd")

# COMMAND ----------

# MAGIC %md
# MAGIC ### prata_kev

# COMMAND ----------

kev = (spark.table("bronze_kev")
    .select(
        padronizar_cve(F.col("cveID")).alias("cve_id"),
        F.trim("vendorProject").alias("fornecedor"),
        F.trim("product").alias("produto"),
        F.to_date("dateAdded").alias("data_inclusao"),
        F.to_date("dueDate").alias("data_prazo"),
        (F.col("knownRansomwareCampaignUse") == "Known").alias("ransomware_conhecido"),  # R8
        cwe_principal(F.coalesce("cwes", F.array().cast("array<string>"))).alias("cwe_principal"),
        F.col("catalogVersion").alias("versao_catalogo"))
    .dropDuplicates(["cve_id"]))
gravar(kev, "prata_kev")

# COMMAND ----------

# MAGIC %md
# MAGIC ### prata_epss (atual e retrato de 01/01/2025)

# COMMAND ----------

def prata_epss(origem):
    return (spark.table(origem)
        .select(padronizar_cve(F.col("cve")).alias("cve_id"),
                F.col("epss").cast("double").alias("epss"),                  # R9
                F.col("percentile").cast("double").alias("epss_percentil"),
                F.to_date("data_score").alias("data_score"),
                "versao_modelo")
        .dropDuplicates(["cve_id"]))

gravar(prata_epss("bronze_epss_atual"), "prata_epss_atual")
gravar(prata_epss("bronze_epss_corte"), "prata_epss_corte")

# COMMAND ----------

# MAGIC %md
# MAGIC ### prata_cwe
# MAGIC Catálogo da MITRE acrescido dos códigos genéricos usados pelo NVD, que não existem na MITRE.

# COMMAND ----------

especiais = spark.createDataFrame([
    ("NVD-CWE-Other", "Outra (classificação genérica do NVD)", "Especial"),
    ("NVD-CWE-noinfo", "Informação insuficiente (NVD)", "Especial"),
    ("SEM-CWE", "Sem CWE atribuída", "Especial"),
], "cwe_id string, nome_cwe string, abstracao string")

cwe = (spark.table("bronze_cwe")
    .select(F.concat(F.lit("CWE-"), F.trim("cwe_numero")).alias("cwe_id"),
            F.col("nome").alias("nome_cwe"), "abstracao")
    .unionByName(especiais))
gravar(cwe, "prata_cwe")

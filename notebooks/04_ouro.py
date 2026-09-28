# Databricks notebook source
# MAGIC %md
# MAGIC # 04 · Camada ouro — modelo dimensional
# MAGIC
# MAGIC Constelação de fatos (esquema estrela com duas tabelas fato que compartilham dimensões):
# MAGIC
# MAGIC * **`fato_cve`** — grão: *uma CVE publicada no NVD entre 2021-01-01 e 2025-12-31* (não rejeitada).
# MAGIC   Mede gravidade (CVSS), probabilidade prevista de exploração (EPSS atual e de 01/01/2025) e
# MAGIC   exploração confirmada (presença no KEV, data e tempo até a inclusão).
# MAGIC * **`fato_kev`** — grão: *uma entrada do catálogo KEV* (catálogo inteiro, qualquer ano de publicação).
# MAGIC   Mede prazo de correção exigido pela CISA, associação a ransomware e EPSS.
# MAGIC * Dimensões: `dim_data` (papéis: publicação, inclusão no KEV, prazo), `dim_cwe`,
# MAGIC   `dim_perfil_cvss` (dimensão *junk* com as métricas de explorabilidade) e `dim_produto`.
# MAGIC
# MAGIC Diagrama e catálogo completo: pasta `catalogo/` do repositório. Os comentários de tabela e
# MAGIC coluna gravados abaixo levam o catálogo para dentro do Unity Catalog (aba *Catalog Explorer*).

# COMMAND ----------

# MAGIC %run ./00_configuracao

# COMMAND ----------

from pyspark.sql import functions as F
from pyspark.sql.window import Window

def gravar(df, tabela):
    df.write.mode("overwrite").option("overwriteSchema", "true").saveAsTable(tabela)
    print(f"{tabela:24s} {spark.table(tabela).count():>9,d} linhas")

# Em reexecuções, remove as chaves estrangeiras antes de sobrescrever as dimensões referenciadas
for fato in ["fato_cve", "fato_kev"]:
    if spark.catalog.tableExists(fato):
        for fk in ["fk_cve_data", "fk_cve_cwe", "fk_cve_perfil", "fk_kev_produto", "fk_kev_data", "fk_kev_cwe"]:
            try:
                spark.sql(f"ALTER TABLE {fato} DROP CONSTRAINT IF EXISTS {fk}")
            except Exception:
                pass

def chave_data(col):
    return F.date_format(col, "yyyyMMdd").cast("int")

def com_chave(df, nome_chave, ordem):
    return df.withColumn(nome_chave, F.row_number().over(Window.orderBy(*ordem))).select(nome_chave, *df.columns)

nvd = spark.table("prata_nvd")
kev = spark.table("prata_kev")
epss = spark.table("prata_epss_atual")
epss_corte = spark.table("prata_epss_corte")

# COMMAND ----------

# MAGIC %md
# MAGIC ### Dimensões

# COMMAND ----------

dim_data = (spark.sql("SELECT explode(sequence(DATE'2002-01-01', DATE'2026-12-31', INTERVAL 1 DAY)) AS data")
    .select(chave_data("data").alias("sk_data"), "data",
            F.year("data").alias("ano"), F.quarter("data").alias("trimestre"),
            F.month("data").alias("mes"), F.dayofweek("data").alias("dia_semana")))
gravar(dim_data, "dim_data")

# CWEs citadas no NVD/KEV que não constam da visão 1000 da MITRE entram como "não catalogadas"
cwe = spark.table("prata_cwe")
citadas = nvd.select(F.col("cwe_principal").alias("cwe_id")).union(kev.select(F.col("cwe_principal").alias("cwe_id"))).distinct()
faltantes = (citadas.join(cwe, "cwe_id", "left_anti")
    .withColumn("nome_cwe", F.lit("Não catalogada na visão CWE-1000"))
    .withColumn("abstracao", F.lit("Desconhecida")))
gravar(com_chave(cwe.unionByName(faltantes), "sk_cwe", ["cwe_id"]), "dim_cwe")

perfil = (nvd.select(F.col("cvss_vetor_ataque").alias("vetor_ataque"), F.col("cvss_complexidade").alias("complexidade"),
                     F.col("cvss_privilegios").alias("privilegios"), F.col("cvss_interacao").alias("interacao_usuario"))
          .distinct())
gravar(com_chave(perfil, "sk_perfil_cvss", perfil.columns), "dim_perfil_cvss")

gravar(com_chave(kev.select("fornecedor", "produto").distinct(), "sk_produto", ["fornecedor", "produto"]), "dim_produto")

# COMMAND ----------

# MAGIC %md
# MAGIC ### fato_cve

# COMMAND ----------

dim_cwe = spark.table("dim_cwe").select("sk_cwe", F.col("cwe_id").alias("cwe_principal"))
dim_perfil = spark.table("dim_perfil_cvss")

pop = nvd.filter(F.col("data_publicacao").between(INICIO_POPULACAO, FIM_POPULACAO))
fato_cve = (pop
    .join(dim_perfil,
          (pop.cvss_vetor_ataque == dim_perfil.vetor_ataque) & (pop.cvss_complexidade == dim_perfil.complexidade) &
          (pop.cvss_privilegios == dim_perfil.privilegios) & (pop.cvss_interacao == dim_perfil.interacao_usuario), "left")
    .join(dim_cwe, "cwe_principal", "left")
    .join(kev.select("cve_id", "data_inclusao", "ransomware_conhecido"), "cve_id", "left")
    .join(epss.select("cve_id", "epss", "epss_percentil"), "cve_id", "left")
    .join(epss_corte.select("cve_id", F.col("epss").alias("epss_2025_01_01"),
                            F.col("epss_percentil").alias("epss_percentil_2025_01_01")), "cve_id", "left")
    .select(
        "cve_id",
        chave_data("data_publicacao").alias("sk_data_publicacao"),
        "sk_cwe", "sk_perfil_cvss",
        "cvss_versao", "cvss_score", "faixa_cvss",
        "epss", "epss_percentil", "epss_2025_01_01", "epss_percentil_2025_01_01",
        F.col("data_inclusao").isNotNull().alias("em_kev"),
        chave_data("data_inclusao").alias("sk_data_inclusao_kev"),
        F.datediff("data_inclusao", "data_publicacao").alias("dias_ate_kev"),
        "ransomware_conhecido"))
gravar(fato_cve, "fato_cve")

# COMMAND ----------

# MAGIC %md
# MAGIC ### fato_kev

# COMMAND ----------

populacao = spark.table("fato_cve").select("cve_id", F.lit(True).alias("na_populacao_nvd"))
fato_kev = (kev
    .join(spark.table("dim_produto"), ["fornecedor", "produto"], "left")
    .join(dim_cwe, "cwe_principal", "left")
    .join(epss.select("cve_id", "epss", "epss_percentil"), "cve_id", "left")
    .join(populacao, "cve_id", "left")
    .select(
        "cve_id", "sk_produto",
        chave_data("data_inclusao").alias("sk_data_inclusao"),
        chave_data("data_prazo").alias("sk_data_prazo"),
        "sk_cwe", "ransomware_conhecido",
        F.datediff("data_prazo", "data_inclusao").alias("prazo_dias"),
        "epss", "epss_percentil",
        F.coalesce("na_populacao_nvd", F.lit(False)).alias("na_populacao_nvd")))
gravar(fato_kev, "fato_kev")

# COMMAND ----------

# MAGIC %md
# MAGIC ### Catálogo no Unity Catalog: comentários e chaves (informativas)

# COMMAND ----------

COMENTARIOS = {
    "fato_cve": ("Uma linha por CVE publicada no NVD entre 2021 e 2025 (exceto rejeitadas).", {
        "cve_id": "Identificador CVE (chave degenerada).",
        "sk_data_publicacao": "FK dim_data: data de publicação no NVD.",
        "sk_cwe": "FK dim_cwe: CWE principal (regra R7).",
        "sk_perfil_cvss": "FK dim_perfil_cvss: métricas de explorabilidade do CVSS.",
        "cvss_versao": "Versão do CVSS usada (3.1 ou 3.0); nula se a CVE não tem CVSS v3.",
        "cvss_score": "Nota base CVSS v3.x, 0 a 10; nula se ausente.",
        "faixa_cvss": "Nenhuma, Baixa, Média, Alta, Crítica ou Sem CVSS.",
        "epss": "Probabilidade de exploração nos próximos 30 dias (EPSS, retrato atual), 0 a 1.",
        "epss_percentil": "Percentil do EPSS atual entre todas as CVEs, 0 a 1.",
        "epss_2025_01_01": "EPSS no retrato de 01/01/2025 (teste prospectivo).",
        "epss_percentil_2025_01_01": "Percentil EPSS em 01/01/2025.",
        "em_kev": "true se a CVE consta do catálogo KEV da CISA (exploração confirmada).",
        "sk_data_inclusao_kev": "FK dim_data: data de inclusão no KEV; nula se não está no KEV.",
        "dias_ate_kev": "Dias entre a publicação no NVD e a inclusão no KEV; pode ser negativo.",
        "ransomware_conhecido": "true se a CISA registra uso conhecido em ransomware; nula fora do KEV.",
    }),
    "fato_kev": ("Uma linha por entrada do catálogo KEV da CISA (catálogo completo).", {
        "cve_id": "Identificador CVE (chave degenerada).",
        "sk_produto": "FK dim_produto.",
        "sk_data_inclusao": "FK dim_data: data de inclusão no KEV.",
        "sk_data_prazo": "FK dim_data: prazo de correção para órgãos federais dos EUA.",
        "sk_cwe": "FK dim_cwe: CWE principal informada pela CISA.",
        "ransomware_conhecido": "true = uso conhecido em ransomware; false = sem evidência pública.",
        "prazo_dias": "Dias entre inclusão e prazo de correção.",
        "epss": "EPSS atual da CVE.",
        "epss_percentil": "Percentil EPSS atual.",
        "na_populacao_nvd": "true se a CVE também está em fato_cve (publicada 2021-2025).",
    }),
    "dim_data": ("Calendário diário de 2002 a 2026.", {}),
    "dim_cwe": ("Fraquezas (CWE) da MITRE, visão 1000, mais códigos genéricos do NVD.", {}),
    "dim_perfil_cvss": ("Combinações das métricas de explorabilidade do CVSS v3 (dimensão junk).", {}),
    "dim_produto": ("Fornecedor e produto afetados, conforme o catálogo KEV.", {}),
}
for tabela, (desc, colunas) in COMENTARIOS.items():
    spark.sql(f"COMMENT ON TABLE {tabela} IS '{desc}'")
    for col, texto in colunas.items():
        spark.sql(f"ALTER TABLE {tabela} ALTER COLUMN {col} COMMENT '{texto}'")

# COMMAND ----------

# Chaves primárias e estrangeiras informativas (não impostas pelo Delta, mas documentam o modelo)
RESTRICOES = [
    "ALTER TABLE dim_data ALTER COLUMN sk_data SET NOT NULL",
    "ALTER TABLE dim_data ADD CONSTRAINT pk_dim_data PRIMARY KEY (sk_data)",
    "ALTER TABLE dim_cwe ALTER COLUMN sk_cwe SET NOT NULL",
    "ALTER TABLE dim_cwe ADD CONSTRAINT pk_dim_cwe PRIMARY KEY (sk_cwe)",
    "ALTER TABLE dim_perfil_cvss ALTER COLUMN sk_perfil_cvss SET NOT NULL",
    "ALTER TABLE dim_perfil_cvss ADD CONSTRAINT pk_dim_perfil PRIMARY KEY (sk_perfil_cvss)",
    "ALTER TABLE dim_produto ALTER COLUMN sk_produto SET NOT NULL",
    "ALTER TABLE dim_produto ADD CONSTRAINT pk_dim_produto PRIMARY KEY (sk_produto)",
    "ALTER TABLE fato_cve ADD CONSTRAINT fk_cve_data FOREIGN KEY (sk_data_publicacao) REFERENCES dim_data",
    "ALTER TABLE fato_cve ADD CONSTRAINT fk_cve_cwe FOREIGN KEY (sk_cwe) REFERENCES dim_cwe",
    "ALTER TABLE fato_cve ADD CONSTRAINT fk_cve_perfil FOREIGN KEY (sk_perfil_cvss) REFERENCES dim_perfil_cvss",
    "ALTER TABLE fato_kev ADD CONSTRAINT fk_kev_produto FOREIGN KEY (sk_produto) REFERENCES dim_produto",
    "ALTER TABLE fato_kev ADD CONSTRAINT fk_kev_data FOREIGN KEY (sk_data_inclusao) REFERENCES dim_data",
    "ALTER TABLE fato_kev ADD CONSTRAINT fk_kev_cwe FOREIGN KEY (sk_cwe) REFERENCES dim_cwe",
]
for comando in RESTRICOES:
    try:
        spark.sql(comando)
    except Exception as erro:  # restrição já existente em reexecuções
        print(f"ignorado: {comando[:70]}… ({type(erro).__name__})")

# COMMAND ----------

display(spark.sql("SHOW TABLES"))

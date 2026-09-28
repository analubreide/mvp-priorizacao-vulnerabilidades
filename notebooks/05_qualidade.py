# Databricks notebook source
# MAGIC %md
# MAGIC # 05 · Qualidade dos dados
# MAGIC
# MAGIC Avalia cada atributo relevante nas dimensões de completude, unicidade, conformidade,
# MAGIC consistência, acurácia, atualidade, integridade referencial e cobertura entre fontes.
# MAGIC
# MAGIC As regras estão em `scripts/regras_qualidade.py` (arquivo único, também usado pela réplica
# MAGIC local). O resultado é gravado na tabela `qualidade_relatorio`.
# MAGIC
# MAGIC * **violação** — problema que precisaria de tratamento; o esperado é 0.
# MAGIC * **informativo** — característica conhecida da fonte que condiciona a análise (ex.: CVEs sem CVSS).

# COMMAND ----------

# MAGIC %run ./00_configuracao

# COMMAND ----------

import os, sys
caminho_notebook = dbutils.notebook.entry_point.getDbutils().notebook().getContext().notebookPath().get()
sys.path.append("/Workspace" + os.path.dirname(os.path.dirname(caminho_notebook)) + "/scripts")
from regras_qualidade import consultas

linhas = []
for r, sql_total, sql_viol in consultas("spark"):
    total = spark.sql(sql_total).first()[0]
    viol = spark.sql(sql_viol).first()[0]
    linhas.append((r["tabela"], r["atributo"], r["dimensao"], r["regra"], r["tipo"],
                   int(total), int(viol), round(100 * viol / total, 2) if total else None, r["tratamento"]))

relatorio = spark.createDataFrame(linhas,
    "tabela string, atributo string, dimensao string, regra string, tipo string, "
    "total long, fora_da_regra long, pct double, tratamento string")
relatorio.write.mode("overwrite").option("overwriteSchema", "true").saveAsTable("qualidade_relatorio")
display(relatorio)

# COMMAND ----------

# MAGIC %md
# MAGIC ### Perfil dos atributos numéricos da camada ouro (mínimo, máximo, nulos)

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT 'cvss_score' AS atributo, MIN(cvss_score) AS minimo, MAX(cvss_score) AS maximo,
# MAGIC        ROUND(AVG(cvss_score), 3) AS media, COUNT_IF(cvss_score IS NULL) AS nulos, COUNT(*) AS total FROM fato_cve
# MAGIC UNION ALL
# MAGIC SELECT 'epss', MIN(epss), MAX(epss), ROUND(AVG(epss), 3), COUNT_IF(epss IS NULL), COUNT(*) FROM fato_cve
# MAGIC UNION ALL
# MAGIC SELECT 'epss_2025_01_01', MIN(epss_2025_01_01), MAX(epss_2025_01_01), ROUND(AVG(epss_2025_01_01), 3),
# MAGIC        COUNT_IF(epss_2025_01_01 IS NULL), COUNT(*) FROM fato_cve
# MAGIC UNION ALL
# MAGIC SELECT 'dias_ate_kev', MIN(dias_ate_kev), MAX(dias_ate_kev), ROUND(AVG(dias_ate_kev), 3),
# MAGIC        COUNT_IF(dias_ate_kev IS NULL), COUNT(*) FROM fato_cve
# MAGIC UNION ALL
# MAGIC SELECT 'prazo_dias (fato_kev)', MIN(prazo_dias), MAX(prazo_dias), ROUND(AVG(prazo_dias), 3),
# MAGIC        COUNT_IF(prazo_dias IS NULL), COUNT(*) FROM fato_kev

# COMMAND ----------

# MAGIC %md
# MAGIC ### Distribuição dos atributos categóricos

# COMMAND ----------

# MAGIC %sql
# MAGIC SELECT 'faixa_cvss' AS atributo, faixa_cvss AS categoria, COUNT(*) AS n FROM fato_cve GROUP BY faixa_cvss
# MAGIC UNION ALL
# MAGIC SELECT 'cvss_versao', COALESCE(cvss_versao, '(nulo)'), COUNT(*) FROM fato_cve GROUP BY cvss_versao
# MAGIC UNION ALL
# MAGIC SELECT 'vetor_ataque', p.vetor_ataque, COUNT(*) FROM fato_cve f JOIN dim_perfil_cvss p USING (sk_perfil_cvss) GROUP BY p.vetor_ataque
# MAGIC UNION ALL
# MAGIC SELECT 'privilegios', p.privilegios, COUNT(*) FROM fato_cve f JOIN dim_perfil_cvss p USING (sk_perfil_cvss) GROUP BY p.privilegios
# MAGIC UNION ALL
# MAGIC SELECT 'interacao_usuario', p.interacao_usuario, COUNT(*) FROM fato_cve f JOIN dim_perfil_cvss p USING (sk_perfil_cvss) GROUP BY p.interacao_usuario
# MAGIC UNION ALL
# MAGIC SELECT 'ransomware_conhecido (fato_kev)', CAST(ransomware_conhecido AS STRING), COUNT(*) FROM fato_kev GROUP BY ransomware_conhecido
# MAGIC ORDER BY atributo, n DESC

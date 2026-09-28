# Databricks notebook source
# MAGIC %md
# MAGIC # 06 · Análise — respostas às perguntas de negócio
# MAGIC
# MAGIC Todas as consultas usam apenas a camada ouro (`fato_cve`, `fato_kev` e dimensões).
# MAGIC Cada célula SQL começa com `-- consulta: <nome>`; o mesmo texto é executado pela réplica
# MAGIC local (`scripts/analise_local.py`), o que garante que os números do README e os do
# MAGIC Databricks venham das mesmas consultas.
# MAGIC
# MAGIC **Convenções**
# MAGIC * *Explorada* = consta do catálogo KEV da CISA (exploração confirmada em ambiente real).
# MAGIC * *Esforço* de uma política = quantas CVEs ela manda corrigir.
# MAGIC * *Cobertura* = fração das CVEs exploradas que a política captura (sensibilidade/recall).
# MAGIC * *Eficiência* = fração das CVEs selecionadas que foram de fato exploradas (precisão).

# COMMAND ----------

# MAGIC %run ./00_configuracao

# COMMAND ----------

# MAGIC %md
# MAGIC ## Visão geral da população

# COMMAND ----------

# MAGIC %sql
# MAGIC -- consulta: resumo
# MAGIC SELECT COUNT(*)                                        AS cves_publicadas_2021_2025,
# MAGIC        SUM(CAST(em_kev AS INT))                        AS exploradas_kev,
# MAGIC        ROUND(100.0 * SUM(CAST(em_kev AS INT)) / COUNT(*), 3) AS taxa_exploracao_pct,
# MAGIC        COUNT_IF(cvss_score IS NULL)                    AS sem_cvss,
# MAGIC        COUNT_IF(epss IS NULL)                          AS sem_epss,
# MAGIC        (SELECT COUNT(*) FROM fato_kev)                 AS entradas_catalogo_kev
# MAGIC FROM fato_cve

# COMMAND ----------

# MAGIC %md
# MAGIC ## P1 · Que fração das CVEs é explorada, por faixa de severidade CVSS?

# COMMAND ----------

# MAGIC %sql
# MAGIC -- consulta: p1_faixa_cvss
# MAGIC SELECT faixa_cvss,
# MAGIC        COUNT(*)                                                    AS cves,
# MAGIC        ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER (), 1)          AS pct_das_cves,
# MAGIC        SUM(CAST(em_kev AS INT))                                    AS exploradas,
# MAGIC        ROUND(100.0 * SUM(CAST(em_kev AS INT)) / SUM(SUM(CAST(em_kev AS INT))) OVER (), 1) AS pct_das_exploradas,
# MAGIC        ROUND(100.0 * SUM(CAST(em_kev AS INT)) / COUNT(*), 3)       AS taxa_exploracao_pct
# MAGIC FROM fato_cve
# MAGIC GROUP BY faixa_cvss
# MAGIC ORDER BY CASE faixa_cvss WHEN 'Crítica' THEN 1 WHEN 'Alta' THEN 2 WHEN 'Média' THEN 3
# MAGIC                          WHEN 'Baixa' THEN 4 WHEN 'Nenhuma' THEN 5 ELSE 6 END

# COMMAND ----------

# MAGIC %sql
# MAGIC -- consulta: p1_por_ano
# MAGIC SELECT d.ano                                                 AS ano_publicacao,
# MAGIC        COUNT(*)                                              AS cves,
# MAGIC        SUM(CAST(f.em_kev AS INT))                            AS exploradas,
# MAGIC        ROUND(100.0 * SUM(CAST(f.em_kev AS INT)) / COUNT(*), 3) AS taxa_exploracao_pct,
# MAGIC        ROUND(100.0 * COUNT_IF(f.cvss_score >= 7) / COUNT(*), 1) AS pct_cvss_alta_ou_critica,
# MAGIC        ROUND(100.0 * COUNT_IF(f.cvss_score IS NULL) / COUNT(*), 1) AS pct_sem_cvss
# MAGIC FROM fato_cve f JOIN dim_data d ON d.sk_data = f.sk_data_publicacao
# MAGIC GROUP BY d.ano
# MAGIC ORDER BY d.ano

# COMMAND ----------

# MAGIC %md
# MAGIC ## P2 · Priorizar por CVSS alto é eficiente? Comparação com EPSS no mesmo esforço
# MAGIC
# MAGIC Usa o EPSS **atual**. Atenção: o EPSS de hoje já incorpora sinais de exploração observados
# MAGIC depois da publicação, o que favorece o EPSS nesta comparação. A pergunta P3 corrige esse viés.

# COMMAND ----------

# MAGIC %sql
# MAGIC -- consulta: p2_politicas_atual
# MAGIC WITH base AS (
# MAGIC   SELECT cvss_score, epss, CAST(em_kev AS INT) AS kev,
# MAGIC          ROW_NUMBER() OVER (ORDER BY epss DESC NULLS LAST, cve_id) AS rank_epss
# MAGIC   FROM fato_cve),
# MAGIC tot AS (SELECT COUNT(*) AS n, SUM(kev) AS n_kev,
# MAGIC                COUNT_IF(cvss_score >= 9) AS n_crit, COUNT_IF(cvss_score >= 7) AS n_alta FROM base),
# MAGIC pol AS (
# MAGIC   SELECT 1 AS ordem, 'CVSS >= 9 (Crítica)' AS politica, COUNT(*) AS esforco, SUM(kev) AS capturadas FROM base WHERE cvss_score >= 9
# MAGIC   UNION ALL SELECT 2, 'EPSS top-N, mesmo esforço de CVSS >= 9', COUNT(*), SUM(kev) FROM base, tot WHERE rank_epss <= tot.n_crit
# MAGIC   UNION ALL SELECT 3, 'CVSS >= 7 (Alta ou Crítica)', COUNT(*), SUM(kev) FROM base WHERE cvss_score >= 7
# MAGIC   UNION ALL SELECT 4, 'EPSS top-N, mesmo esforço de CVSS >= 7', COUNT(*), SUM(kev) FROM base, tot WHERE rank_epss <= tot.n_alta
# MAGIC   UNION ALL SELECT 5, 'EPSS >= 0,10', COUNT(*), SUM(kev) FROM base WHERE epss >= 0.10
# MAGIC   UNION ALL SELECT 6, 'EPSS >= 0,01', COUNT(*), SUM(kev) FROM base WHERE epss >= 0.01)
# MAGIC SELECT politica, esforco,
# MAGIC        ROUND(100.0 * esforco / tot.n, 1)          AS esforco_pct,
# MAGIC        capturadas,
# MAGIC        ROUND(100.0 * capturadas / tot.n_kev, 1)   AS cobertura_pct,
# MAGIC        ROUND(100.0 * capturadas / NULLIF(esforco, 0), 2) AS eficiencia_pct
# MAGIC FROM pol, tot
# MAGIC ORDER BY ordem

# COMMAND ----------

# MAGIC %md
# MAGIC ## P3 · Teste prospectivo: com a informação de 01/01/2025, qual critério antecipava as explorações seguintes?
# MAGIC
# MAGIC * População: CVEs publicadas de 2021 a 2024 que **ainda não** estavam no KEV em 01/01/2025.
# MAGIC * Desfecho: entrar no KEV entre 01/01/2025 e a data da versão baixada do catálogo.
# MAGIC * Preditores: CVSS e EPSS **do retrato de 01/01/2025** (CVE sem EPSS naquela data = 0).

# COMMAND ----------

# MAGIC %sql
# MAGIC -- consulta: p3_politicas_prospectivo
# MAGIC WITH base AS (
# MAGIC   SELECT cve_id, cvss_score, COALESCE(epss_2025_01_01, 0) AS epss_corte,
# MAGIC          CASE WHEN sk_data_inclusao_kev >= 20250101 THEN 1 ELSE 0 END AS kev_depois
# MAGIC   FROM fato_cve
# MAGIC   WHERE sk_data_publicacao < 20250101
# MAGIC     AND (sk_data_inclusao_kev IS NULL OR sk_data_inclusao_kev >= 20250101)),
# MAGIC ranq AS (SELECT *, ROW_NUMBER() OVER (ORDER BY epss_corte DESC, cve_id) AS rank_epss FROM base),
# MAGIC tot AS (SELECT COUNT(*) AS n, SUM(kev_depois) AS n_kev,
# MAGIC                COUNT_IF(cvss_score >= 9) AS n_crit, COUNT_IF(cvss_score >= 7) AS n_alta FROM base),
# MAGIC pol AS (
# MAGIC   SELECT 1 AS ordem, 'CVSS >= 9 (Crítica)' AS politica, COUNT(*) AS esforco, SUM(kev_depois) AS capturadas FROM ranq WHERE cvss_score >= 9
# MAGIC   UNION ALL SELECT 2, 'EPSS top-N, mesmo esforço de CVSS >= 9', COUNT(*), SUM(kev_depois) FROM ranq, tot WHERE rank_epss <= tot.n_crit
# MAGIC   UNION ALL SELECT 3, 'CVSS >= 7 (Alta ou Crítica)', COUNT(*), SUM(kev_depois) FROM ranq WHERE cvss_score >= 7
# MAGIC   UNION ALL SELECT 4, 'EPSS top-N, mesmo esforço de CVSS >= 7', COUNT(*), SUM(kev_depois) FROM ranq, tot WHERE rank_epss <= tot.n_alta
# MAGIC   UNION ALL SELECT 5, 'EPSS >= 0,10', COUNT(*), SUM(kev_depois) FROM ranq WHERE epss_corte >= 0.10
# MAGIC   UNION ALL SELECT 6, 'EPSS >= 0,01', COUNT(*), SUM(kev_depois) FROM ranq WHERE epss_corte >= 0.01
# MAGIC   UNION ALL SELECT 7, 'CVSS >= 7 e EPSS >= 0,01', COUNT(*), SUM(kev_depois) FROM ranq WHERE cvss_score >= 7 AND epss_corte >= 0.01)
# MAGIC SELECT politica, esforco,
# MAGIC        ROUND(100.0 * esforco / tot.n, 1)          AS esforco_pct,
# MAGIC        capturadas, tot.n_kev                      AS exploradas_no_periodo,
# MAGIC        ROUND(100.0 * capturadas / tot.n_kev, 1)   AS cobertura_pct,
# MAGIC        ROUND(100.0 * capturadas / NULLIF(esforco, 0), 2) AS eficiencia_pct
# MAGIC FROM pol, tot
# MAGIC ORDER BY ordem

# COMMAND ----------

# MAGIC %md
# MAGIC Curva esforço × cobertura: ordena as CVEs por cada critério e acumula as exploradas capturadas.

# COMMAND ----------

import matplotlib.pyplot as plt

pros = spark.sql("""
  SELECT cve_id, cvss_score, COALESCE(epss_2025_01_01, 0) AS epss_corte,
         CASE WHEN sk_data_inclusao_kev >= 20250101 THEN 1 ELSE 0 END AS kev_depois
  FROM fato_cve
  WHERE sk_data_publicacao < 20250101 AND (sk_data_inclusao_kev IS NULL OR sk_data_inclusao_kev >= 20250101)
""").toPandas()

fig, ax = plt.subplots(figsize=(8, 5))
for coluna, rotulo in [("epss_corte", "EPSS em 01/01/2025"), ("cvss_score", "CVSS")]:
    ordenado = pros.sort_values([coluna, "cve_id"], ascending=[False, True], na_position="last")
    ax.plot(range(1, len(ordenado) + 1), ordenado["kev_depois"].cumsum() / pros["kev_depois"].sum() * 100, label=rotulo)
ax.set_xscale("log"); ax.set_xlabel("CVEs corrigidas (esforço, escala log)"); ax.set_ylabel("Exploradas capturadas (%)")
ax.set_title("Teste prospectivo: esforço × cobertura"); ax.legend(); ax.grid(alpha=.3)
display(fig)

# COMMAND ----------

# MAGIC %md
# MAGIC ## P4 · Que características técnicas estão super-representadas entre as exploradas?
# MAGIC `razao` = taxa de exploração da categoria ÷ taxa geral. Acima de 1, a categoria é mais explorada que a média.

# COMMAND ----------

# MAGIC %sql
# MAGIC -- consulta: p4_perfil_cvss
# MAGIC WITH base AS (
# MAGIC   SELECT p.vetor_ataque, p.complexidade, p.privilegios, p.interacao_usuario, CAST(f.em_kev AS INT) AS kev
# MAGIC   FROM fato_cve f JOIN dim_perfil_cvss p ON p.sk_perfil_cvss = f.sk_perfil_cvss
# MAGIC   WHERE p.vetor_ataque <> 'N/D'),
# MAGIC geral AS (SELECT SUM(kev) * 1.0 / COUNT(*) AS taxa FROM base),
# MAGIC cat AS (
# MAGIC   SELECT 'Vetor de ataque' AS metrica, vetor_ataque AS categoria, COUNT(*) AS cves, SUM(kev) AS exploradas FROM base GROUP BY vetor_ataque
# MAGIC   UNION ALL SELECT 'Complexidade', complexidade, COUNT(*), SUM(kev) FROM base GROUP BY complexidade
# MAGIC   UNION ALL SELECT 'Privilégios exigidos', privilegios, COUNT(*), SUM(kev) FROM base GROUP BY privilegios
# MAGIC   UNION ALL SELECT 'Interação do usuário', interacao_usuario, COUNT(*), SUM(kev) FROM base GROUP BY interacao_usuario)
# MAGIC SELECT metrica, categoria, cves, exploradas,
# MAGIC        ROUND(100.0 * exploradas / cves, 3)             AS taxa_exploracao_pct,
# MAGIC        ROUND((exploradas * 1.0 / cves) / geral.taxa, 2) AS razao
# MAGIC FROM cat, geral
# MAGIC ORDER BY metrica, razao DESC

# COMMAND ----------

# MAGIC %sql
# MAGIC -- consulta: p4_cwe
# MAGIC WITH base AS (
# MAGIC   SELECT c.cwe_id, c.nome_cwe, CAST(f.em_kev AS INT) AS kev
# MAGIC   FROM fato_cve f JOIN dim_cwe c ON c.sk_cwe = f.sk_cwe),
# MAGIC geral AS (SELECT SUM(kev) * 1.0 / COUNT(*) AS taxa, SUM(kev) AS n_kev FROM base)
# MAGIC SELECT cwe_id, nome_cwe,
# MAGIC        COUNT(*)                                                AS cves,
# MAGIC        SUM(kev)                                                AS exploradas,
# MAGIC        ROUND(100.0 * SUM(kev) / MAX(geral.n_kev), 1)           AS pct_das_exploradas,
# MAGIC        ROUND(100.0 * SUM(kev) / COUNT(*), 2)                   AS taxa_exploracao_pct,
# MAGIC        ROUND((SUM(kev) * 1.0 / COUNT(*)) / MAX(geral.taxa), 1) AS razao
# MAGIC FROM base, geral
# MAGIC GROUP BY cwe_id, nome_cwe
# MAGIC HAVING SUM(kev) >= 10
# MAGIC ORDER BY exploradas DESC
# MAGIC LIMIT 12

# COMMAND ----------

# MAGIC %md
# MAGIC ## P5 · Quais fornecedores e produtos concentram as vulnerabilidades exploradas e o uso em ransomware?
# MAGIC Catálogo KEV completo (todas as CVEs já exploradas, de qualquer ano de publicação).

# COMMAND ----------

# MAGIC %sql
# MAGIC -- consulta: p5_fornecedores
# MAGIC SELECT p.fornecedor,
# MAGIC        COUNT(*)                                                      AS entradas_kev,
# MAGIC        ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER (), 1)            AS pct_do_catalogo,
# MAGIC        COUNT(DISTINCT p.produto)                                     AS produtos_distintos,
# MAGIC        COUNT_IF(k.ransomware_conhecido)                              AS com_ransomware,
# MAGIC        ROUND(100.0 * COUNT_IF(k.ransomware_conhecido) / COUNT(*), 1) AS pct_ransomware
# MAGIC FROM fato_kev k JOIN dim_produto p ON p.sk_produto = k.sk_produto
# MAGIC GROUP BY p.fornecedor
# MAGIC ORDER BY entradas_kev DESC
# MAGIC LIMIT 12

# COMMAND ----------

# MAGIC %sql
# MAGIC -- consulta: p5_produtos
# MAGIC SELECT p.fornecedor, p.produto,
# MAGIC        COUNT(*)                                                      AS entradas_kev,
# MAGIC        COUNT_IF(k.ransomware_conhecido)                              AS com_ransomware
# MAGIC FROM fato_kev k JOIN dim_produto p ON p.sk_produto = k.sk_produto
# MAGIC GROUP BY p.fornecedor, p.produto
# MAGIC ORDER BY entradas_kev DESC, p.fornecedor
# MAGIC LIMIT 12

# COMMAND ----------

# MAGIC %sql
# MAGIC -- consulta: p5_concentracao
# MAGIC WITH por_fornecedor AS (
# MAGIC   SELECT p.fornecedor, COUNT(*) AS n,
# MAGIC          ROW_NUMBER() OVER (ORDER BY COUNT(*) DESC, p.fornecedor) AS posicao
# MAGIC   FROM fato_kev k JOIN dim_produto p ON p.sk_produto = k.sk_produto
# MAGIC   GROUP BY p.fornecedor)
# MAGIC SELECT COUNT(*)                                                         AS fornecedores,
# MAGIC        ROUND(100.0 * SUM(CASE WHEN posicao <= 5 THEN n END) / SUM(n), 1)  AS pct_top5,
# MAGIC        ROUND(100.0 * SUM(CASE WHEN posicao <= 10 THEN n END) / SUM(n), 1) AS pct_top10,
# MAGIC        COUNT_IF(n = 1)                                                  AS fornecedores_com_uma_entrada,
# MAGIC        (SELECT ROUND(100.0 * COUNT_IF(ransomware_conhecido) / COUNT(*), 1) FROM fato_kev) AS pct_ransomware_geral
# MAGIC FROM por_fornecedor

# COMMAND ----------

# MAGIC %md
# MAGIC ## P6 · Quanto tempo passa entre a publicação de uma CVE e sua inclusão no KEV?
# MAGIC Somente CVEs da população (publicadas 2021–2025) que entraram no KEV.

# COMMAND ----------

# MAGIC %sql
# MAGIC -- consulta: p6_faixas_tempo
# MAGIC SELECT CASE WHEN dias_ate_kev < 0 THEN '1. Antes da publicação no NVD'
# MAGIC             WHEN dias_ate_kev <= 7 THEN '2. 0 a 7 dias'
# MAGIC             WHEN dias_ate_kev <= 30 THEN '3. 8 a 30 dias'
# MAGIC             WHEN dias_ate_kev <= 90 THEN '4. 31 a 90 dias'
# MAGIC             WHEN dias_ate_kev <= 365 THEN '5. 91 a 365 dias'
# MAGIC             ELSE '6. Mais de 1 ano' END                       AS faixa_tempo,
# MAGIC        COUNT(*)                                               AS cves,
# MAGIC        ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER (), 1)     AS pct,
# MAGIC        ROUND(100.0 * SUM(COUNT(*)) OVER (ORDER BY MIN(dias_ate_kev)) / SUM(COUNT(*)) OVER (), 1) AS pct_acumulado
# MAGIC FROM fato_cve
# MAGIC WHERE em_kev
# MAGIC GROUP BY 1
# MAGIC ORDER BY 1

# COMMAND ----------

# MAGIC %sql
# MAGIC -- consulta: p6_por_ano
# MAGIC SELECT d.ano                                                     AS ano_publicacao,
# MAGIC        COUNT(*)                                                  AS exploradas,
# MAGIC        MEDIAN(f.dias_ate_kev)                                    AS mediana_dias,
# MAGIC        ROUND(100.0 * COUNT_IF(f.dias_ate_kev <= 7) / COUNT(*), 1)  AS pct_ate_7_dias,
# MAGIC        ROUND(100.0 * COUNT_IF(f.dias_ate_kev <= 30) / COUNT(*), 1) AS pct_ate_30_dias
# MAGIC FROM fato_cve f JOIN dim_data d ON d.sk_data = f.sk_data_publicacao
# MAGIC WHERE f.em_kev
# MAGIC GROUP BY d.ano
# MAGIC ORDER BY d.ano

# COMMAND ----------

# MAGIC %sql
# MAGIC -- consulta: p6_prazo_cisa
# MAGIC SELECT MEDIAN(prazo_dias)                                AS mediana_prazo_dias,
# MAGIC        ROUND(100.0 * COUNT_IF(prazo_dias <= 21) / COUNT(*), 1) AS pct_prazo_ate_21_dias,
# MAGIC        MIN(prazo_dias) AS minimo, MAX(prazo_dias) AS maximo
# MAGIC FROM fato_kev k JOIN dim_data d ON d.sk_data = k.sk_data_inclusao
# MAGIC WHERE d.ano >= 2022

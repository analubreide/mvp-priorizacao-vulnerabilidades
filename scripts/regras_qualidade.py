"""
Regras de qualidade de dados, por atributo.

Arquivo único usado tanto pelo notebook 05_qualidade (Databricks, Spark SQL) quanto pela
réplica local (scripts/analise_local.py, DuckDB). Cada regra conta quantas linhas a violam.

Campos:
    tabela     tabela avaliada
    atributo   atributo (ou par de atributos) avaliado
    dimensao   completude, unicidade, conformidade, consistência, acurácia, integridade ou cobertura
    regra      o que se espera do dado
    violacao   condição SQL (cláusula WHERE) que identifica as linhas fora da regra,
               ou consulta completa iniciada por SELECT que devolve uma única contagem
    tipo       "violação" (problema a tratar) ou "informativo" (característica conhecida da fonte)
    tratamento o que o pipeline faz a respeito
"""

REGEX_CVE = "^CVE-[0-9]{4}-[0-9]{4,}$"

REGRAS = [
    # ---------------------------------------------------------------- NVD (bruto)
    dict(tabela="bronze_nvd", atributo="cve_id", dimensao="completude", regra="não nulo",
         violacao="cve_id IS NULL", tipo="violação", tratamento="—"),
    dict(tabela="bronze_nvd", atributo="cve_id", dimensao="conformidade", regra=f"segue o padrão {REGEX_CVE}",
         violacao=f"NOT cve_id RLIKE '{REGEX_CVE}'", tipo="violação", tratamento="—"),
    dict(tabela="bronze_nvd", atributo="cve_id", dimensao="unicidade", regra="uma linha por CVE",
         violacao="SELECT COUNT(*) - COUNT(DISTINCT cve_id) FROM bronze_nvd", tipo="violação",
         tratamento="R2: mantém a versão mais recente"),
    dict(tabela="bronze_nvd", atributo="status_nvd", dimensao="conformidade",
         regra="status válido da API do NVD",
         violacao="status_nvd NOT IN ('Analyzed','Modified','Awaiting Analysis','Undergoing Analysis','Received','Deferred','Rejected')",
         tipo="violação", tratamento="—"),
    dict(tabela="bronze_nvd", atributo="status_nvd", dimensao="acurácia", regra="CVE não rejeitada",
         violacao="status_nvd = 'Rejected'", tipo="violação", tratamento="R3: excluída na prata"),
    dict(tabela="bronze_nvd", atributo="status_nvd", dimensao="atualidade",
         regra="CVE já analisada pelo NVD (Analyzed/Modified)",
         violacao="status_nvd IN ('Awaiting Analysis','Undergoing Analysis','Received','Deferred')",
         tipo="informativo", tratamento="Mantida; explica parte das CVEs sem CVSS/CWE"),
    dict(tabela="bronze_nvd", atributo="publicado_em / modificado_em", dimensao="consistência",
         regra="publicação anterior ou igual à última modificação",
         violacao="CAST(publicado_em AS TIMESTAMP) > CAST(modificado_em AS TIMESTAMP)", tipo="violação", tratamento="—"),
    dict(tabela="bronze_nvd", atributo="cvss_score", dimensao="completude", regra="CVE com nota CVSS v3.x",
         violacao="cvss_score IS NULL AND status_nvd <> 'Rejected'", tipo="informativo",
         tratamento="R6: faixa 'Sem CVSS', mantida"),
    dict(tabela="bronze_nvd", atributo="cvss_score", dimensao="conformidade", regra="entre 0 e 10",
         violacao="cvss_score < 0 OR cvss_score > 10", tipo="violação", tratamento="R5: vira nulo"),
    dict(tabela="bronze_nvd", atributo="cvss_versao", dimensao="conformidade", regra="3.0 ou 3.1 quando presente",
         violacao="cvss_versao IS NOT NULL AND cvss_versao NOT IN ('3.0','3.1')", tipo="violação", tratamento="—"),
    dict(tabela="bronze_nvd", atributo="cvss_score / cvss_severidade", dimensao="consistência",
         regra="severidade compatível com a nota (tabela oficial CVSS v3)",
         violacao="""cvss_score IS NOT NULL AND cvss_severidade <> CASE
                        WHEN cvss_score = 0 THEN 'NONE' WHEN cvss_score < 4 THEN 'LOW'
                        WHEN cvss_score < 7 THEN 'MEDIUM' WHEN cvss_score < 9 THEN 'HIGH' ELSE 'CRITICAL' END""",
         tipo="violação", tratamento="R5: faixa recalculada a partir da nota"),
    dict(tabela="bronze_nvd", atributo="cvss_fonte", dimensao="consistência",
         regra="nota atribuída pelo próprio NVD (nvd@nist.gov)",
         violacao="cvss_score IS NOT NULL AND cvss_fonte <> 'nvd@nist.gov'", tipo="informativo",
         tratamento="R4: aceita a nota do fabricante (CNA) na falta da do NVD"),
    dict(tabela="bronze_nvd", atributo="cvss_vetor_ataque", dimensao="conformidade",
         regra="NETWORK, ADJACENT_NETWORK, LOCAL ou PHYSICAL",
         violacao="cvss_vetor_ataque NOT IN ('NETWORK','ADJACENT_NETWORK','LOCAL','PHYSICAL')", tipo="violação", tratamento="—"),
    dict(tabela="bronze_nvd", atributo="cvss_complexidade", dimensao="conformidade", regra="LOW ou HIGH",
         violacao="cvss_complexidade NOT IN ('LOW','HIGH')", tipo="violação", tratamento="—"),
    dict(tabela="bronze_nvd", atributo="cvss_privilegios", dimensao="conformidade", regra="NONE, LOW ou HIGH",
         violacao="cvss_privilegios NOT IN ('NONE','LOW','HIGH')", tipo="violação", tratamento="—"),
    dict(tabela="bronze_nvd", atributo="cvss_interacao", dimensao="conformidade", regra="NONE ou REQUIRED",
         violacao="cvss_interacao NOT IN ('NONE','REQUIRED')", tipo="violação", tratamento="—"),
    dict(tabela="bronze_nvd", atributo="cwes", dimensao="completude", regra="ao menos uma CWE",
         violacao="(cwes IS NULL OR size(cwes) = 0) AND status_nvd <> 'Rejected'", tipo="informativo",
         tratamento="R7: CWE principal 'SEM-CWE'"),
    dict(tabela="prata_nvd", atributo="cwe_principal", dimensao="acurácia",
         regra="CWE específica (não genérica do NVD)",
         violacao="cwe_principal IN ('NVD-CWE-Other','NVD-CWE-noinfo','SEM-CWE')", tipo="informativo",
         tratamento="Mantida como categoria própria em dim_cwe"),

    # ---------------------------------------------------------------- KEV (bruto)
    dict(tabela="bronze_kev", atributo="cveID", dimensao="completude", regra="não nulo",
         violacao="cveID IS NULL", tipo="violação", tratamento="—"),
    dict(tabela="bronze_kev", atributo="cveID", dimensao="conformidade", regra=f"segue o padrão {REGEX_CVE}",
         violacao=f"NOT cveID RLIKE '{REGEX_CVE}'", tipo="violação", tratamento="—"),
    dict(tabela="bronze_kev", atributo="cveID", dimensao="unicidade", regra="uma linha por CVE",
         violacao="SELECT COUNT(*) - COUNT(DISTINCT cveID) FROM bronze_kev", tipo="violação", tratamento="dropDuplicates"),
    dict(tabela="bronze_kev", atributo="vendorProject", dimensao="completude", regra="não nulo e não vazio",
         violacao="vendorProject IS NULL OR TRIM(vendorProject) = ''", tipo="violação", tratamento="—"),
    dict(tabela="bronze_kev", atributo="vendorProject", dimensao="consistência",
         regra="cada fornecedor com uma única grafia (ignorando maiúsculas/espaços)",
         violacao="""SELECT COUNT(*) FROM (SELECT LOWER(TRIM(vendorProject)) AS f FROM bronze_kev
                     GROUP BY LOWER(TRIM(vendorProject)) HAVING COUNT(DISTINCT vendorProject) > 1) AS x""",
         tipo="violação", tratamento="R1 aplica TRIM"),
    dict(tabela="bronze_kev", atributo="product", dimensao="completude", regra="não nulo e não vazio",
         violacao="product IS NULL OR TRIM(product) = ''", tipo="violação", tratamento="—"),
    dict(tabela="bronze_kev", atributo="dateAdded", dimensao="conformidade",
         regra="data entre o lançamento do catálogo (2021-11-03) e a versão baixada",
         violacao="CAST(dateAdded AS DATE) < DATE'2021-11-03' OR CAST(dateAdded AS DATE) > CAST(dateReleased AS DATE)",
         tipo="violação", tratamento="—"),
    dict(tabela="bronze_kev", atributo="dateAdded / dueDate", dimensao="consistência", regra="prazo posterior à inclusão",
         violacao="CAST(dueDate AS DATE) < CAST(dateAdded AS DATE)", tipo="violação", tratamento="—"),
    dict(tabela="bronze_kev", atributo="knownRansomwareCampaignUse", dimensao="conformidade", regra="Known ou Unknown",
         violacao="knownRansomwareCampaignUse NOT IN ('Known','Unknown')", tipo="violação", tratamento="R8"),
    dict(tabela="bronze_kev", atributo="cwes", dimensao="completude", regra="ao menos uma CWE",
         violacao="cwes IS NULL OR size(cwes) = 0", tipo="informativo", tratamento="R7: 'SEM-CWE'"),

    # ---------------------------------------------------------------- EPSS
    dict(tabela="prata_epss_atual", atributo="cve_id", dimensao="conformidade", regra=f"segue o padrão {REGEX_CVE}",
         violacao=f"NOT cve_id RLIKE '{REGEX_CVE}'", tipo="violação", tratamento="—"),
    dict(tabela="bronze_epss_atual", atributo="cve", dimensao="unicidade", regra="uma linha por CVE",
         violacao="SELECT COUNT(*) - COUNT(DISTINCT cve) FROM bronze_epss_atual", tipo="violação", tratamento="dropDuplicates"),
    dict(tabela="prata_epss_atual", atributo="epss", dimensao="conformidade", regra="entre 0 e 1, não nulo",
         violacao="epss IS NULL OR epss < 0 OR epss > 1", tipo="violação", tratamento="—"),
    dict(tabela="prata_epss_atual", atributo="epss_percentil", dimensao="conformidade", regra="entre 0 e 1, não nulo",
         violacao="epss_percentil IS NULL OR epss_percentil < 0 OR epss_percentil > 1", tipo="violação", tratamento="—"),
    dict(tabela="prata_epss_corte", atributo="epss", dimensao="conformidade", regra="entre 0 e 1, não nulo",
         violacao="epss IS NULL OR epss < 0 OR epss > 1", tipo="violação", tratamento="—"),

    # ---------------------------------------------------------------- Ouro / entre fontes
    dict(tabela="fato_cve", atributo="sk_cwe", dimensao="integridade", regra="chave encontrada em dim_cwe",
         violacao="sk_cwe IS NULL", tipo="violação", tratamento="—"),
    dict(tabela="fato_cve", atributo="sk_perfil_cvss", dimensao="integridade", regra="chave encontrada em dim_perfil_cvss",
         violacao="sk_perfil_cvss IS NULL", tipo="violação", tratamento="—"),
    dict(tabela="fato_cve", atributo="epss", dimensao="completude", regra="CVE com EPSS atual",
         violacao="epss IS NULL", tipo="informativo", tratamento="Fica fora das políticas por EPSS"),
    dict(tabela="fato_cve", atributo="epss_2025_01_01", dimensao="completude",
         regra="CVE publicada até 2024 com EPSS em 01/01/2025",
         violacao="epss_2025_01_01 IS NULL AND sk_data_publicacao < 20250101", tipo="informativo",
         tratamento="Tratada como EPSS = 0 no teste prospectivo"),
    dict(tabela="fato_cve", atributo="dias_ate_kev", dimensao="consistência",
         regra="inclusão no KEV não anterior à publicação no NVD",
         violacao="dias_ate_kev < 0", tipo="informativo",
         tratamento="Mantida: a exploração pode ser anterior à publicação (zero-day)"),
    dict(tabela="fato_kev", atributo="sk_produto", dimensao="integridade", regra="chave encontrada em dim_produto",
         violacao="sk_produto IS NULL", tipo="violação", tratamento="—"),
    dict(tabela="fato_kev", atributo="sk_cwe", dimensao="integridade", regra="chave encontrada em dim_cwe",
         violacao="sk_cwe IS NULL", tipo="violação", tratamento="—"),
    dict(tabela="fato_kev", atributo="epss", dimensao="completude", regra="CVE do KEV com EPSS atual",
         violacao="epss IS NULL", tipo="informativo", tratamento="—"),
    dict(tabela="fato_kev", atributo="cve_id", dimensao="cobertura",
         regra="CVE do KEV com identificador de 2021 a 2025 presente na população do NVD",
         violacao="NOT na_populacao_nvd AND CAST(SUBSTRING(cve_id, 5, 4) AS INT) BETWEEN 2021 AND 2025",
         tipo="informativo", tratamento="Publicada fora do recorte (ex.: ID reservado em um ano e publicado em outro)"),
]


def consultas(dialeto="spark"):
    """Gera, para cada regra, a consulta de total e a de violações no dialeto pedido."""
    for r in REGRAS:
        v = r["violacao"].strip()
        sql_viol = v if v.upper().startswith("SELECT") else f"SELECT COUNT(*) FROM {r['tabela']} WHERE {v}"
        sql_total = f"SELECT COUNT(*) FROM {r['tabela']}"
        if dialeto == "duckdb":
            sql_viol = traduzir_para_duckdb(sql_viol)
        yield r, sql_total, sql_viol


def traduzir_para_duckdb(sql):
    import re
    sql = re.sub(r"(\w+)\s+RLIKE\s+'([^']*)'", r"regexp_matches(\1, '\2')", sql)
    return sql.replace("size(", "len(")

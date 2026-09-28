"""
Réplica local (pandas) do pipeline executado no Databricks (notebooks 02 a 04).

Serve para validar as regras de transformação fora da nuvem. Gera as mesmas tabelas,
com os mesmos nomes e colunas, das camadas bronze, prata e ouro, gravadas em
dados/processados/<tabela>.parquet. As consultas SQL dos notebooks 05 e 06 rodam sobre
esses arquivos sem alteração (ver scripts/analise_local.py).

Uso (a partir da raiz do repositório):
    python scripts/pipeline_local.py
"""
import gzip
import json
import re
from pathlib import Path

import numpy as np
import pandas as pd

RAIZ = Path(__file__).resolve().parents[1]
BRUTOS = RAIZ / "dados" / "brutos"
SAIDA = RAIZ / "dados" / "processados"

INICIO_POPULACAO = pd.Timestamp("2021-01-01")
FIM_POPULACAO = pd.Timestamp("2025-12-31")
CWE_ESPECIAIS = [
    ("NVD-CWE-Other", "Outra (classificação genérica do NVD)", "Especial"),
    ("NVD-CWE-noinfo", "Informação insuficiente (NVD)", "Especial"),
    ("SEM-CWE", "Sem CWE atribuída", "Especial"),
]
COLS_PERFIL = ["cvss_vetor_ataque", "cvss_complexidade", "cvss_privilegios", "cvss_interacao"]


def faixa_cvss(score):  # R5 / R6
    if pd.isna(score):
        return "Sem CVSS"
    if score == 0:
        return "Nenhuma"
    if score < 4:
        return "Baixa"
    if score < 7:
        return "Média"
    if score < 9:
        return "Alta"
    return "Crítica"


def cwe_principal(lista):  # R7
    lista = list(lista) if lista is not None else []
    especificas = [c for c in lista if re.fullmatch(r"CWE-\d+", c)]
    if especificas:
        return especificas[0]
    return lista[0] if lista else "SEM-CWE"


def padronizar_cve(s):  # R1
    return s.str.strip().str.upper()


def sk_data(s):
    return s.dt.strftime("%Y%m%d").astype("Int64")


# ---------------------------------------------------------------- bronze
def bronze():
    nvd = pd.read_json(BRUTOS / "nvd_cves.ndjson.gz", lines=True, compression="gzip", dtype=False)

    kev_json = json.load(open(BRUTOS / "kev.json", encoding="utf-8"))
    kev = pd.DataFrame(kev_json["vulnerabilities"])
    kev.insert(0, "dateReleased", kev_json["dateReleased"])
    kev.insert(0, "catalogVersion", kev_json["catalogVersion"])

    def epss(arquivo):
        with gzip.open(BRUTOS / arquivo, "rt", encoding="utf-8") as f:
            meta = dict(i.split(":", 1) for i in f.readline().strip().lstrip("#").split(","))
        df = pd.read_csv(BRUTOS / arquivo, comment="#", dtype=str)
        df["versao_modelo"] = meta["model_version"]
        df["data_score"] = meta["score_date"][:10]
        return df

    cwe = pd.read_csv(BRUTOS / "cwe_1000.csv.zip", index_col=False, dtype=str)[
        ["CWE-ID", "Name", "Weakness Abstraction", "Status"]]
    cwe.columns = ["cwe_numero", "nome", "abstracao", "status"]

    return {
        "bronze_nvd": nvd, "bronze_kev": kev, "bronze_cwe": cwe,
        "bronze_epss_atual": epss("epss_scores-current.csv.gz"),
        "bronze_epss_corte": epss("epss_scores-2025-01-01.csv.gz"),
    }


# ---------------------------------------------------------------- prata
def prata(b):
    nvd = b["bronze_nvd"].copy()
    nvd["cve_id"] = padronizar_cve(nvd["cve_id"])
    nvd["modificado_em"] = pd.to_datetime(nvd["modificado_em"])
    nvd = nvd.sort_values("modificado_em").drop_duplicates("cve_id", keep="last")          # R2
    nvd = nvd[nvd["status_nvd"] != "Rejected"].copy()                                     # R3
    nvd["data_publicacao"] = pd.to_datetime(nvd["publicado_em"]).dt.normalize()
    nvd["cvss_score"] = pd.to_numeric(nvd["cvss_score"], errors="coerce")
    nvd["cvss_score"] = nvd["cvss_score"].where(nvd["cvss_score"].between(0, 10))         # R5
    nvd["faixa_cvss"] = nvd["cvss_score"].map(faixa_cvss)
    nvd["cwe_principal"] = nvd["cwes"].map(cwe_principal)
    nvd[COLS_PERFIL] = nvd[COLS_PERFIL].fillna("N/D")
    nvd = nvd.drop(columns="publicado_em")

    k = b["bronze_kev"]
    kev = pd.DataFrame({
        "cve_id": padronizar_cve(k["cveID"]),
        "fornecedor": k["vendorProject"].str.strip(),
        "produto": k["product"].str.strip(),
        "data_inclusao": pd.to_datetime(k["dateAdded"]),
        "data_prazo": pd.to_datetime(k["dueDate"]),
        "ransomware_conhecido": k["knownRansomwareCampaignUse"].eq("Known"),                # R8
        "cwe_principal": k["cwes"].map(cwe_principal),
        "versao_catalogo": k["catalogVersion"],
    }).drop_duplicates("cve_id")

    def epss(df):
        return pd.DataFrame({
            "cve_id": padronizar_cve(df["cve"]),
            "epss": df["epss"].astype(float),                                               # R9
            "epss_percentil": df["percentile"].astype(float),
            "data_score": pd.to_datetime(df["data_score"]),
            "versao_modelo": df["versao_modelo"],
        }).drop_duplicates("cve_id")

    c = b["bronze_cwe"]
    cwe = pd.concat([
        pd.DataFrame({"cwe_id": "CWE-" + c["cwe_numero"].str.strip(), "nome_cwe": c["nome"], "abstracao": c["abstracao"]}),
        pd.DataFrame(CWE_ESPECIAIS, columns=["cwe_id", "nome_cwe", "abstracao"]),
    ], ignore_index=True)

    return {
        "prata_nvd": nvd, "prata_kev": kev, "prata_cwe": cwe,
        "prata_epss_atual": epss(b["bronze_epss_atual"]),
        "prata_epss_corte": epss(b["bronze_epss_corte"]),
    }


# ---------------------------------------------------------------- ouro
def com_chave(df, nome, ordem):
    df = df.sort_values(ordem).reset_index(drop=True)
    df.insert(0, nome, df.index + 1)
    return df


def ouro(p):
    nvd, kev, epss, epss_corte = p["prata_nvd"], p["prata_kev"], p["prata_epss_atual"], p["prata_epss_corte"]

    datas = pd.DataFrame({"data": pd.date_range("2002-01-01", "2026-12-31", freq="D")})
    dim_data = pd.DataFrame({
        "sk_data": sk_data(datas["data"]), "data": datas["data"],
        "ano": datas["data"].dt.year, "trimestre": datas["data"].dt.quarter,
        "mes": datas["data"].dt.month,
        "dia_semana": (datas["data"].dt.dayofweek + 1) % 7 + 1,   # 1 = domingo, como no Spark
    })

    cwe = p["prata_cwe"]
    citadas = set(nvd["cwe_principal"]) | set(kev["cwe_principal"])
    faltantes = sorted(citadas - set(cwe["cwe_id"]))
    cwe = pd.concat([cwe, pd.DataFrame({"cwe_id": faltantes, "nome_cwe": "Não catalogada na visão CWE-1000",
                                        "abstracao": "Desconhecida"})], ignore_index=True)
    dim_cwe = com_chave(cwe, "sk_cwe", ["cwe_id"])

    perfil = nvd[COLS_PERFIL].drop_duplicates()
    perfil.columns = ["vetor_ataque", "complexidade", "privilegios", "interacao_usuario"]
    dim_perfil = com_chave(perfil, "sk_perfil_cvss", list(perfil.columns))

    dim_produto = com_chave(kev[["fornecedor", "produto"]].drop_duplicates(), "sk_produto", ["fornecedor", "produto"])

    map_cwe = dict(zip(dim_cwe["cwe_id"], dim_cwe["sk_cwe"]))

    pop = nvd[nvd["data_publicacao"].between(INICIO_POPULACAO, FIM_POPULACAO)]
    pop = pop.merge(dim_perfil, left_on=COLS_PERFIL, right_on=list(perfil.columns), how="left")
    pop = pop.merge(kev[["cve_id", "data_inclusao", "ransomware_conhecido"]], on="cve_id", how="left")
    pop = pop.merge(epss[["cve_id", "epss", "epss_percentil"]], on="cve_id", how="left")
    pop = pop.merge(epss_corte[["cve_id", "epss", "epss_percentil"]].rename(columns={
        "epss": "epss_2025_01_01", "epss_percentil": "epss_percentil_2025_01_01"}), on="cve_id", how="left")
    fato_cve = pd.DataFrame({
        "cve_id": pop["cve_id"],
        "sk_data_publicacao": sk_data(pop["data_publicacao"]),
        "sk_cwe": pop["cwe_principal"].map(map_cwe).astype("Int64"),
        "sk_perfil_cvss": pop["sk_perfil_cvss"].astype("Int64"),
        "cvss_versao": pop["cvss_versao"],
        "cvss_score": pop["cvss_score"],
        "faixa_cvss": pop["faixa_cvss"],
        "epss": pop["epss"],
        "epss_percentil": pop["epss_percentil"],
        "epss_2025_01_01": pop["epss_2025_01_01"],
        "epss_percentil_2025_01_01": pop["epss_percentil_2025_01_01"],
        "em_kev": pop["data_inclusao"].notna(),
        "sk_data_inclusao_kev": sk_data(pop["data_inclusao"]),
        "dias_ate_kev": (pop["data_inclusao"] - pop["data_publicacao"]).dt.days.astype("Int64"),
        "ransomware_conhecido": pop["ransomware_conhecido"].astype("boolean"),
    })

    k = kev.merge(dim_produto, on=["fornecedor", "produto"], how="left")
    k = k.merge(epss[["cve_id", "epss", "epss_percentil"]], on="cve_id", how="left")
    fato_kev = pd.DataFrame({
        "cve_id": k["cve_id"],
        "sk_produto": k["sk_produto"],
        "sk_data_inclusao": sk_data(k["data_inclusao"]),
        "sk_data_prazo": sk_data(k["data_prazo"]),
        "sk_cwe": k["cwe_principal"].map(map_cwe).astype("Int64"),
        "ransomware_conhecido": k["ransomware_conhecido"],
        "prazo_dias": (k["data_prazo"] - k["data_inclusao"]).dt.days,
        "epss": k["epss"],
        "epss_percentil": k["epss_percentil"],
        "na_populacao_nvd": k["cve_id"].isin(fato_cve["cve_id"]),
    })

    return {"dim_data": dim_data, "dim_cwe": dim_cwe, "dim_perfil_cvss": dim_perfil,
            "dim_produto": dim_produto, "fato_cve": fato_cve, "fato_kev": fato_kev}


def main():
    SAIDA.mkdir(parents=True, exist_ok=True)
    b = bronze()
    p = prata(b)
    o = ouro(p)
    for nome, df in {**b, **p, **o}.items():
        df.to_parquet(SAIDA / f"{nome}.parquet", index=False)
        print(f"{nome:20s} {len(df):>9,d} linhas")


if __name__ == "__main__":
    main()

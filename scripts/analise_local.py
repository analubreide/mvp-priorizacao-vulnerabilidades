"""
Executa localmente, sobre as tabelas geradas por pipeline_local.py, exatamente as mesmas
consultas do Databricks:

* as regras de qualidade de scripts/regras_qualidade.py (notebook 05);
* cada célula SQL do notebook 06_analise.py marcada com "-- consulta: <nome>".

Grava os resultados em docs/resultados/*.csv e os gráficos do README em docs/figuras/*.png.

Uso (a partir da raiz do repositório):
    python scripts/analise_local.py
"""
import re
from pathlib import Path

import duckdb
import matplotlib.pyplot as plt
import pandas as pd

from regras_qualidade import consultas as consultas_qualidade

RAIZ = Path(__file__).resolve().parents[1]
PROCESSADOS = RAIZ / "dados" / "processados"
RESULTADOS = RAIZ / "docs" / "resultados"
FIGURAS = RAIZ / "docs" / "figuras"

# Paleta (slots 1 e 2 da paleta categórica de referência + tinta neutra)
AZUL, LARANJA, CINZA, TINTA, TINTA_2 = "#2a78d6", "#eb6834", "#b8b7b1", "#0b0b0b", "#52514e"
plt.rcParams.update({
    "font.size": 10, "axes.edgecolor": CINZA, "axes.labelcolor": TINTA_2, "xtick.color": TINTA_2,
    "ytick.color": TINTA_2, "axes.spines.top": False, "axes.spines.right": False,
    "axes.titleweight": "bold", "axes.titlesize": 12, "axes.titlelocation": "left",
    "figure.dpi": 150, "savefig.bbox": "tight", "axes.grid": True, "grid.color": "#e6e5e0", "grid.linewidth": .6,
})


def conectar():
    con = duckdb.connect()
    for arq in PROCESSADOS.glob("*.parquet"):
        con.execute(f"CREATE VIEW {arq.stem} AS SELECT * FROM read_parquet('{arq.as_posix()}')")
    return con


def consultas_notebook():
    texto = (RAIZ / "notebooks" / "06_analise.py").read_text(encoding="utf-8")
    for celula in texto.split("# COMMAND ----------"):
        linhas = [l[len("# MAGIC "):] if l.startswith("# MAGIC ") else l[len("# MAGIC"):]
                  for l in celula.strip().splitlines() if l.startswith("# MAGIC")]
        if linhas and linhas[0].strip() == "%sql":
            sql = "\n".join(linhas[1:])
            nome = re.search(r"--\s*consulta:\s*(\w+)", sql).group(1)
            yield nome, sql


def qualidade(con):
    linhas = []
    for r, sql_total, sql_viol in consultas_qualidade("duckdb"):
        total = con.execute(sql_total).fetchone()[0]
        viol = con.execute(sql_viol).fetchone()[0]
        linhas.append({"tabela": r["tabela"], "atributo": r["atributo"], "dimensao": r["dimensao"],
                       "regra": r["regra"], "tipo": r["tipo"], "total": total, "fora_da_regra": viol,
                       "pct": round(100 * viol / total, 2) if total else None, "tratamento": r["tratamento"]})
    return pd.DataFrame(linhas)


# ---------------------------------------------------------------- gráficos
def rotulo_barra(ax, barras, fmt):
    for b in barras:
        ax.annotate(fmt(b.get_width()), (b.get_width(), b.get_y() + b.get_height() / 2),
                    xytext=(4, 0), textcoords="offset points", va="center", fontsize=9, color=TINTA)


def fig_p1(r):
    df = r["p1_faixa_cvss"].iloc[::-1]
    fig, ax = plt.subplots(figsize=(8, 3.6))
    barras = ax.barh(df["faixa_cvss"], df["taxa_exploracao_pct"], color=AZUL, height=.6)
    rotulo_barra(ax, barras, lambda v: f"{v:.2f}%".replace(".", ","))
    ax.set_xlabel("CVEs da faixa que entraram no KEV (%)")
    ax.set_title("P1 · Taxa de exploração confirmada por faixa de severidade CVSS")
    ax.grid(axis="y", visible=False)
    fig.savefig(FIGURAS / "p1_taxa_por_faixa.png")


def fig_politicas(df, nome, titulo):
    df = df.iloc[::-1]
    cores = [LARANJA if p.startswith("EPSS") else AZUL if p.startswith("CVSS >= ") and " e " not in p else CINZA
             for p in df["politica"]]
    fig, axes = plt.subplots(1, 2, figsize=(10, 3.8), sharey=True)
    for ax, col, rot in [(axes[0], "esforco_pct", "Esforço: % das CVEs a corrigir"),
                         (axes[1], "cobertura_pct", "Cobertura: % das exploradas capturadas")]:
        barras = ax.barh(df["politica"], df[col], color=cores, height=.6)
        rotulo_barra(ax, barras, lambda v: f"{v:.1f}%".replace(".", ","))
        ax.set_xlabel(rot); ax.grid(axis="y", visible=False)
        ax.set_xlim(0, max(df[col].max() * 1.18, 10))
    fig.suptitle(titulo, x=0.01, ha="left", fontweight="bold", fontsize=12)
    fig.text(0.01, -0.04, "Azul = políticas por CVSS · Laranja = políticas por EPSS · Cinza = combinada",
             color=TINTA_2, fontsize=9)
    fig.savefig(FIGURAS / nome)


def fig_curva(con):
    pros = con.execute("""
      SELECT cve_id, cvss_score, COALESCE(epss_2025_01_01, 0) AS epss_corte,
             CASE WHEN sk_data_inclusao_kev >= 20250101 THEN 1 ELSE 0 END AS kev_depois
      FROM fato_cve
      WHERE sk_data_publicacao < 20250101 AND (sk_data_inclusao_kev IS NULL OR sk_data_inclusao_kev >= 20250101)
    """).df()
    fig, ax = plt.subplots(figsize=(8, 4.6))
    total = pros["kev_depois"].sum()
    curvas = {}
    for coluna, rotulo, cor in [("epss_corte", "EPSS em 01/01/2025", LARANJA), ("cvss_score", "CVSS", AZUL)]:
        ordenado = pros.sort_values([coluna, "cve_id"], ascending=[False, True], na_position="last")
        y = ordenado["kev_depois"].cumsum().to_numpy() / total * 100
        x = range(1, len(ordenado) + 1)
        ax.plot(x, y, color=cor, linewidth=2, label=rotulo)
        curvas[rotulo] = y
    for esforco in [1000, 10000]:
        ax.axvline(esforco, color=CINZA, linewidth=1, linestyle="--")
        for rotulo, cor in [("EPSS em 01/01/2025", LARANJA), ("CVSS", AZUL)]:
            v = curvas[rotulo][esforco - 1]
            ax.plot(esforco, v, "o", color=cor, markersize=7, markeredgecolor="white", markeredgewidth=2)
            ax.annotate(f"{v:.0f}%", (esforco, v), xytext=(8, -12 if rotulo == "CVSS" else 8),
                        textcoords="offset points", fontsize=9, color=TINTA,
                        bbox=dict(boxstyle="round,pad=0.15", fc="white", ec="none"))
    ax.set_xscale("log")
    ax.set_xlabel("CVEs corrigidas, na ordem do critério (esforço, escala log)")
    ax.set_ylabel("Exploradas em 2025–2026 capturadas (%)")
    ax.set_title("P3 · Teste prospectivo: esforço × cobertura (informação de 01/01/2025)")
    ax.legend(frameon=False, loc="upper left")
    fig.savefig(FIGURAS / "p3_curva_esforco_cobertura.png")
    return pros, curvas


def fig_p4(r):
    df = r["p4_perfil_cvss"].copy()
    df["rotulo"] = df["metrica"] + ": " + df["categoria"]
    df = df.sort_values("razao")
    fig, ax = plt.subplots(figsize=(8, 5))
    cores = [AZUL if v >= 1 else CINZA for v in df["razao"]]
    barras = ax.barh(df["rotulo"], df["razao"], color=cores, height=.6)
    rotulo_barra(ax, barras, lambda v: f"{v:.2f}×".replace(".", ","))
    ax.axvline(1, color=TINTA_2, linewidth=1)
    ax.set_xlabel("Taxa de exploração da categoria ÷ taxa geral (1 = média)")
    ax.set_title("P4 · Perfil técnico das vulnerabilidades exploradas")
    ax.grid(axis="y", visible=False)
    fig.savefig(FIGURAS / "p4_perfil_cvss.png")


def fig_p5(r):
    df = r["p5_fornecedores"].head(10).iloc[::-1]
    fig, ax = plt.subplots(figsize=(8, 4.4))
    sem = df["entradas_kev"] - df["com_ransomware"]
    ax.barh(df["fornecedor"], df["com_ransomware"], color=LARANJA, height=.6, label="Com uso conhecido em ransomware")
    ax.barh(df["fornecedor"], sem, left=df["com_ransomware"] + 0.0, color=AZUL, height=.6,
            label="Sem evidência pública de ransomware", edgecolor="white", linewidth=1)
    for i, (n, pct) in enumerate(zip(df["entradas_kev"], df["pct_do_catalogo"])):
        ax.annotate(f"{n} ({pct:.1f}%)".replace(".", ","), (n, i), xytext=(4, 0), textcoords="offset points",
                    va="center", fontsize=9, color=TINTA)
    ax.set_xlabel("Entradas no catálogo KEV (% do catálogo)")
    ax.set_title("P5 · Os 10 fornecedores com mais vulnerabilidades exploradas")
    ax.legend(frameon=False, loc="lower right"); ax.grid(axis="y", visible=False)
    ax.set_xlim(0, df["entradas_kev"].max() * 1.2)
    fig.savefig(FIGURAS / "p5_fornecedores.png")


def fig_p6(r):
    df = r["p6_faixas_tempo"]
    df = df.assign(rotulo=df["faixa_tempo"].str.slice(3).str.replace("Antes da publicação no NVD", "Antes da\npublicação no NVD"))
    fig, ax = plt.subplots(figsize=(8, 3.8))
    barras = ax.bar(df["rotulo"], df["pct"], color=AZUL, width=.6)
    for b, n in zip(barras, df["cves"]):
        ax.annotate(f"{b.get_height():.1f}%\n(n={n})".replace(".", ","), (b.get_x() + b.get_width() / 2, b.get_height()),
                    xytext=(0, 3), textcoords="offset points", ha="center", fontsize=9, color=TINTA)
    ax.set_ylabel("% das CVEs exploradas")
    ax.set_ylim(0, df["pct"].max() * 1.3)
    ax.set_title("P6 · Tempo entre a publicação no NVD e a inclusão no KEV")
    ax.grid(axis="x", visible=False)
    plt.setp(ax.get_xticklabels(), fontsize=9)
    fig.savefig(FIGURAS / "p6_tempo_ate_kev.png")


def main():
    RESULTADOS.mkdir(parents=True, exist_ok=True)
    FIGURAS.mkdir(parents=True, exist_ok=True)
    con = conectar()

    q = qualidade(con)
    q.to_csv(RESULTADOS / "qualidade_relatorio.csv", index=False)
    print(q.to_string(max_colwidth=45))

    r = {}
    for nome, sql in consultas_notebook():
        r[nome] = con.execute(sql).df()
        r[nome].to_csv(RESULTADOS / f"{nome}.csv", index=False)
        print(f"\n== {nome}\n{r[nome].to_string()}")

    fig_p1(r)
    fig_politicas(r["p2_politicas_atual"], "p2_politicas_atual.png",
                  "P2 · Políticas de priorização (EPSS atual — com viés a favor do EPSS)")
    fig_politicas(r["p3_politicas_prospectivo"], "p3_politicas_prospectivo.png",
                  "P3 · Políticas de priorização no teste prospectivo (informação de 01/01/2025)")
    _, curvas = fig_curva(con)
    for rot, y in curvas.items():
        print(f"curva {rot}: 1.000 CVEs -> {y[999]:.1f}% | 10.000 -> {y[9999]:.1f}%")
    fig_p4(r)
    fig_p5(r)
    fig_p6(r)
    print("\nGráficos gravados em", FIGURAS)


if __name__ == "__main__":
    main()

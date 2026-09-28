"""
Coleta das CVEs publicadas no NVD (NIST) em um intervalo de datas, via API pública 2.0.

Para cada CVE, guarda apenas os campos usados no MVP (id, datas, status, métricas
CVSS v3.x e CWE), em formato NDJSON (uma CVE por linha). O arquivo resultante é a
camada "bronze" do NVD no pipeline.

Uso:
    python scripts/coleta_nvd.py --inicio 2021-01-01 --fim 2025-12-31 --saida dados/brutos/nvd_cves.ndjson

A API sem chave aceita ~5 requisições a cada 30 s; o script espera 6,5 s entre
chamadas. Com chave (variável de ambiente NVD_API_KEY) o intervalo cai para 1 s.
A coleta é retomável: janelas já concluídas ficam registradas em <saida>.progresso.
"""
import argparse
import json
import os
import time
from datetime import date, datetime, timedelta

import requests

URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
POR_PAGINA = 2000
JANELA_DIAS = 90  # a API limita cada consulta a 120 dias


def metrica_cvss(metrics):
    """Escolhe a métrica CVSS v3.x: prioriza a do NVD (Primary); senão, a primeira disponível."""
    for chave in ("cvssMetricV31", "cvssMetricV30"):
        lista = metrics.get(chave) or []
        if not lista:
            continue
        primaria = [m for m in lista if m.get("type") == "Primary"]
        m = (primaria or lista)[0]
        d = m["cvssData"]
        return {
            "cvss_versao": d.get("version"),
            "cvss_fonte": m.get("source"),
            "cvss_score": d.get("baseScore"),
            "cvss_severidade": d.get("baseSeverity"),
            "cvss_vetor_ataque": d.get("attackVector"),
            "cvss_complexidade": d.get("attackComplexity"),
            "cvss_privilegios": d.get("privilegesRequired"),
            "cvss_interacao": d.get("userInteraction"),
            "cvss_explorabilidade": m.get("exploitabilityScore"),
            "cvss_impacto": m.get("impactScore"),
        }
    return {}


def cwes(weaknesses):
    """Lista de CWEs, priorizando a classificação Primary do NVD."""
    ordenadas = sorted(weaknesses or [], key=lambda w: w.get("type") != "Primary")
    vistos = []
    for w in ordenadas:
        for d in w.get("description", []):
            v = d.get("value")
            if v and v not in vistos:
                vistos.append(v)
    return vistos


def extrair(item):
    c = item["cve"]
    registro = {
        "cve_id": c["id"],
        "publicado_em": c.get("published"),
        "modificado_em": c.get("lastModified"),
        "status_nvd": c.get("vulnStatus"),
        "cwes": cwes(c.get("weaknesses")),
    }
    registro.update(metrica_cvss(c.get("metrics", {})))
    return registro


def janelas(inicio, fim):
    atual = inicio
    while atual <= fim:
        fim_janela = min(atual + timedelta(days=JANELA_DIAS - 1), fim)
        yield atual, fim_janela
        atual = fim_janela + timedelta(days=1)


def consultar(sessao, params, pausa):
    for tentativa in range(8):
        r = sessao.get(URL, params=params, timeout=120)
        if r.status_code == 200:
            time.sleep(pausa)
            return r.json()
        espera = pausa * (tentativa + 2)
        print(f"  HTTP {r.status_code}; nova tentativa em {espera:.0f}s")
        time.sleep(espera)
    raise RuntimeError(f"Falha persistente na API do NVD: {params}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--inicio", default="2021-01-01")
    ap.add_argument("--fim", default="2025-12-31")
    ap.add_argument("--saida", default="dados/brutos/nvd_cves.ndjson")
    args = ap.parse_args()

    chave = os.environ.get("NVD_API_KEY")
    pausa = 1.0 if chave else 6.5
    sessao = requests.Session()
    if chave:
        sessao.headers["apiKey"] = chave

    arq_progresso = args.saida + ".progresso"
    concluidas = set()
    if os.path.exists(arq_progresso):
        concluidas = set(open(arq_progresso, encoding="utf-8").read().split())

    inicio = date.fromisoformat(args.inicio)
    fim = date.fromisoformat(args.fim)
    total = 0
    with open(args.saida, "a", encoding="utf-8") as saida, open(arq_progresso, "a", encoding="utf-8") as prog:
        for a, b in janelas(inicio, fim):
            rotulo = f"{a}_{b}"
            if rotulo in concluidas:
                continue
            params = {
                "pubStartDate": f"{a}T00:00:00.000",
                "pubEndDate": f"{b}T23:59:59.999",
                "resultsPerPage": POR_PAGINA,
                "startIndex": 0,
            }
            linhas = []
            while True:
                dados = consultar(sessao, params, pausa)
                linhas.extend(extrair(v) for v in dados.get("vulnerabilities", []))
                params["startIndex"] += POR_PAGINA
                if params["startIndex"] >= dados["totalResults"]:
                    break
            # grava a janela inteira de uma vez, para a retomada não duplicar registros
            for reg in linhas:
                saida.write(json.dumps(reg, ensure_ascii=False) + "\n")
            saida.flush()
            prog.write(rotulo + "\n")
            prog.flush()
            total += len(linhas)
            print(f"{datetime.now():%H:%M:%S} janela {rotulo}: {len(linhas)} CVEs (acumulado nesta execução: {total})")


if __name__ == "__main__":
    main()

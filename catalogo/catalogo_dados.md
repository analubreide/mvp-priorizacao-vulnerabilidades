# Catálogo de Dados

Descreve as tabelas da camada ouro (esquema `workspace.mvp_vuln` no Databricks). Os mesmos
textos de descrição estão gravados como comentários de tabela e de coluna no Unity Catalog
(notebook `04_ouro`). O diagrama do modelo está em [`modelo_dados.md`](modelo_dados.md).

**Colunas de cada tabela:** *Domínio* traz a faixa válida esperada e, entre colchetes, o
mínimo e o máximo observados na carga de 28/09/2026. *Nulo?* informa se o campo admite
nulos e o que a ausência significa.

---

## 1. Fontes e linhagem

| Fonte | Arquivo bruto | Obtenção | Data da coleta | Volume | Formato original | Licença |
|---|---|---|---|---|---|---|
| CISA — Known Exploited Vulnerabilities (KEV) | `kev.json` | Download direto de `cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | 28/09/2026 (catálogo versão 2026.09.27) | 1.728 CVEs · 1,8 MB | JSON | CC0 1.0 |
| NIST — National Vulnerability Database (NVD) | `nvd_cves.ndjson.gz` | API CVE 2.0 (`services.nvd.nist.gov/rest/json/cves/2.0`), filtro `pubStartDate`/`pubEndDate` de 2021-01-01 a 2025-12-31 em janelas de 90 dias, 2.000 registros por página, pelo script `scripts/coleta_nvd.py` | 28/09/2026 | 170.006 CVEs · 70,8 MB (3,4 MB compactado) | JSON da API, reduzido a NDJSON com 15 campos | Domínio público (governo dos EUA) |
| FIRST — EPSS, retrato atual | `epss_scores-current.csv.gz` | Download direto de `epss.empiricalsecurity.com` | 28/09/2026 (modelo v2026.06.15) | 380.224 CVEs · 2,7 MB | CSV compactado | Uso livre com atribuição |
| FIRST — EPSS, retrato histórico | `epss_scores-2025-01-01.csv.gz` | Download direto de `epss.empiricalsecurity.com` | 28/09/2026 (scores de 01/01/2025, modelo v2023.03.01) | 271.765 CVEs · 1,6 MB | CSV compactado | Uso livre com atribuição |
| MITRE — CWE, visão 1000 | `cwe_1000.csv.zip` | Download direto de `cwe.mitre.org/data/csv/1000.csv.zip` | 28/09/2026 | 944 fraquezas · 0,6 MB | CSV compactado | Termos de uso da MITRE |

**Transformações:** bronze = cópia fiel com colunas `_arquivo_origem` e `_carregado_em`;
prata = regras R1 a R9 (notebook `03_prata`, listadas no README); ouro = junções e chaves
substitutas (notebook `04_ouro`). A tabela `bronze_log_coleta` registra a origem, o tamanho e
o horário de cada cópia para o Volume.

---

## 2. `fato_cve`

Grão: uma CVE publicada no NVD entre 01/01/2021 e 31/12/2025, exceto as rejeitadas. **162.145 linhas.**
Linhagem: `prata_nvd` ⟕ `prata_kev` ⟕ `prata_epss_atual` ⟕ `prata_epss_corte` (junções à esquerda por `cve_id`).

| Atributo | Tipo | Descrição | Domínio | Nulo? | Linhagem |
|---|---|---|---|---|---|
| `cve_id` | texto | Identificador da vulnerabilidade (chave degenerada) | padrão `CVE-AAAA-N{4,}`; único | Não | NVD `cve.id`, regra R1 |
| `sk_data_publicacao` | numérico (int) | Chave da data de publicação no NVD | `AAAAMMDD` [20210101 – 20251231] | Não | NVD `published`, truncado para data (UTC) |
| `sk_cwe` | numérico (int) | Chave da CWE principal | chave de `dim_cwe` | Não | NVD `weaknesses`, regra R7 |
| `sk_perfil_cvss` | numérico (int) | Chave da combinação de métricas de explorabilidade | chave de `dim_perfil_cvss` | Não | NVD `metrics.cvssMetricV31/V30` |
| `cvss_versao` | categórico | Versão do CVSS usada | `3.1`, `3.0` | Sim: CVE sem CVSS v3 (3.102 linhas) | NVD `cvssData.version`, regra R4 |
| `cvss_score` | numérico | Nota base CVSS | 0,0 a 10,0 [0,0 – 10,0] | Sim: sem CVSS v3 | NVD `cvssData.baseScore`, regras R4/R5 |
| `faixa_cvss` | categórico | Faixa qualitativa da nota | `Nenhuma` (0), `Baixa` (0,1–3,9), `Média` (4,0–6,9), `Alta` (7,0–8,9), `Crítica` (9,0–10), `Sem CVSS` | Não | Calculada a partir de `cvss_score` (R5/R6) |
| `epss` | numérico | Probabilidade estimada de exploração nos próximos 30 dias, retrato atual | 0 a 1 [0,00051 – 0,99999] | Sim: CVE ausente do EPSS (0 linhas nesta carga) | EPSS `epss`, R9 |
| `epss_percentil` | numérico | Percentil do EPSS atual | 0 a 1 [0,00001 – 1,0] | Idem | EPSS `percentile` |
| `epss_2025_01_01` | numérico | EPSS no retrato de 01/01/2025 | 0 a 1 [0,00042 – 0,97524] | Sim: CVE publicada depois de 01/01/2025 ou ainda sem score naquela data | EPSS histórico |
| `epss_percentil_2025_01_01` | numérico | Percentil do EPSS em 01/01/2025 | 0 a 1 | Idem | EPSS histórico |
| `em_kev` | booleano | CVE com exploração confirmada (consta do KEV) | `true` / `false` | Não | Existência de `cve_id` em `prata_kev` |
| `sk_data_inclusao_kev` | numérico (int) | Chave da data de inclusão no KEV | `AAAAMMDD` [20211103 – 20260918] | Sim: CVE não está no KEV | KEV `dateAdded` |
| `dias_ate_kev` | numérico (int) | Dias entre publicação no NVD e inclusão no KEV | inteiro; negativo = inclusão antes da publicação no NVD [−290 – 1.828] | Sim: CVE não está no KEV | `dateAdded − published` |
| `ransomware_conhecido` | booleano | Uso conhecido em campanhas de ransomware | `true` / `false` | Sim: CVE não está no KEV (161.278 linhas) | KEV `knownRansomwareCampaignUse`, R8 |

## 3. `fato_kev`

Grão: uma entrada do catálogo KEV (catálogo completo). **1.728 linhas.**
Linhagem: `prata_kev` ⟕ `dim_produto` ⟕ `dim_cwe` ⟕ `prata_epss_atual` ⟕ `fato_cve`.

| Atributo | Tipo | Descrição | Domínio | Nulo? | Linhagem |
|---|---|---|---|---|---|
| `cve_id` | texto | Identificador da vulnerabilidade | padrão CVE; único | Não | KEV `cveID`, R1 |
| `sk_produto` | numérico (int) | Chave do fornecedor/produto | chave de `dim_produto` [719 valores] | Não | KEV `vendorProject` + `product` |
| `sk_data_inclusao` | numérico (int) | Chave da data de inclusão no KEV | [20211103 – 20260927] | Não | KEV `dateAdded` |
| `sk_data_prazo` | numérico (int) | Chave do prazo de correção exigido de órgãos federais dos EUA | [20211117 – 20260930] | Não | KEV `dueDate` |
| `sk_cwe` | numérico (int) | Chave da CWE principal informada pela CISA | chave de `dim_cwe` | Não (`SEM-CWE` quando ausente) | KEV `cwes`, R7 |
| `ransomware_conhecido` | booleano | `true` = uso conhecido em ransomware; `false` = **sem evidência pública** (não significa "nunca usado") | `true` / `false` | Não | KEV `knownRansomwareCampaignUse`, R8 |
| `prazo_dias` | numérico (int) | Dias entre a inclusão e o prazo de correção | inteiro ≥ 0 [1 – 184] | Não | `dueDate − dateAdded` |
| `epss` | numérico | EPSS atual da CVE | 0 a 1 [0,00233 – 0,99999] | Sim: CVE fora do EPSS (0 nesta carga) | EPSS atual |
| `epss_percentil` | numérico | Percentil EPSS atual | 0 a 1 | Idem | EPSS atual |
| `na_populacao_nvd` | booleano | CVE também presente em `fato_cve` (publicada 2021–2025) | `true` (867) / `false` (861) | Não | Existência em `fato_cve` |

## 4. Dimensões

### `dim_data` — 9.131 linhas (calendário diário 01/01/2002 a 31/12/2026)

| Atributo | Tipo | Descrição | Domínio | Nulo? |
|---|---|---|---|---|
| `sk_data` | numérico (int) | Chave no formato `AAAAMMDD` (PK) | [20020101 – 20261231] | Não |
| `data` | data | Data do calendário | 2002-01-01 a 2026-12-31 | Não |
| `ano` | numérico (int) | Ano | 2002 – 2026 | Não |
| `trimestre` | numérico (int) | Trimestre | 1 – 4 | Não |
| `mes` | numérico (int) | Mês | 1 – 12 | Não |
| `dia_semana` | numérico (int) | Dia da semana (convenção Spark) | 1 = domingo … 7 = sábado | Não |

### `dim_cwe` — 975 linhas

| Atributo | Tipo | Descrição | Domínio | Nulo? |
|---|---|---|---|---|
| `sk_cwe` | numérico (int) | Chave substituta (PK) | 1 – 975 | Não |
| `cwe_id` | texto | Código da fraqueza | `CWE-n`, `NVD-CWE-Other`, `NVD-CWE-noinfo`, `SEM-CWE`; único | Não |
| `nome_cwe` | texto | Nome oficial da MITRE (em inglês) ou descrição do código especial | texto livre | Não |
| `abstracao` | categórico | Nível de abstração da MITRE | `Pillar`, `Class`, `Base`, `Variant`, `Compound`, `Especial` (códigos do NVD), `Desconhecida` (28 CWEs citadas que não pertencem à visão 1000, como categorias) | Não |

### `dim_perfil_cvss` — 49 linhas (dimensão *junk*)

| Atributo | Tipo | Descrição | Domínio | Nulo? |
|---|---|---|---|---|
| `sk_perfil_cvss` | numérico (int) | Chave substituta (PK) | 1 – 49 | Não |
| `vetor_ataque` | categórico | De onde o ataque pode partir | `NETWORK`, `ADJACENT_NETWORK`, `LOCAL`, `PHYSICAL`, `N/D` (sem CVSS) | Não |
| `complexidade` | categórico | Condições além do controle do atacante | `LOW`, `HIGH`, `N/D` | Não |
| `privilegios` | categórico | Privilégios exigidos do atacante | `NONE`, `LOW`, `HIGH`, `N/D` | Não |
| `interacao_usuario` | categórico | Se a vítima precisa agir (ex.: abrir arquivo) | `NONE`, `REQUIRED`, `N/D` | Não |

### `dim_produto` — 719 linhas (283 fornecedores)

| Atributo | Tipo | Descrição | Domínio | Nulo? |
|---|---|---|---|---|
| `sk_produto` | numérico (int) | Chave substituta (PK) | 1 – 719 | Não |
| `fornecedor` | categórico | Fabricante ou projeto, grafia da CISA | 283 valores | Não |
| `produto` | categórico | Produto afetado, grafia da CISA | texto; pode ser genérico (ex.: "Multiple Products") | Não |

---

## 5. Tabelas de apoio

| Tabela | Conteúdo |
|---|---|
| `bronze_*` | Dados brutos de cada fonte, sem alteração de conteúdo |
| `prata_*` | Dados limpos, tipados e deduplicados (regras R1–R9) |
| `bronze_log_coleta` | Registro de cada cópia de arquivo para o Volume |
| `qualidade_relatorio` | Resultado das 42 regras de qualidade (notebook `05_qualidade`) |

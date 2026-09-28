# Modelo de dados

## Arquitetura em camadas (medalhão) no Databricks

```mermaid
flowchart LR
    subgraph Fontes
        A1[CISA KEV<br/>kev.json]
        A2[NIST NVD<br/>API CVE 2.0]
        A3[FIRST EPSS<br/>atual + 01/01/2025]
        A4[MITRE CWE<br/>visão 1000]
    end
    subgraph Volume["Volume UC: /Volumes/workspace/mvp_vuln/brutos"]
        V[(arquivos brutos)]
    end
    subgraph Bronze
        B1[bronze_kev]
        B2[bronze_nvd]
        B3[bronze_epss_atual<br/>bronze_epss_corte]
        B4[bronze_cwe]
        B5[bronze_log_coleta]
    end
    subgraph Prata
        S1[prata_kev]
        S2[prata_nvd]
        S3[prata_epss_atual<br/>prata_epss_corte]
        S4[prata_cwe]
    end
    subgraph Ouro["Ouro (modelo dimensional)"]
        F1{{fato_cve}}
        F2{{fato_kev}}
        D1[dim_data]
        D2[dim_cwe]
        D3[dim_perfil_cvss]
        D4[dim_produto]
    end
    A1 & A2 & A3 & A4 --> V
    V -->|01_coleta / 02_bronze| B1 & B2 & B3 & B4
    B1 -->|03_prata| S1
    B2 --> S2
    B3 --> S3
    B4 --> S4
    S1 & S2 & S3 & S4 -->|04_ouro| F1 & F2
    F1 & F2 --- D1 & D2
    F1 --- D3
    F2 --- D4
```

## Esquema dimensional (camada ouro)

Constelação de fatos: um **esquema estrela** com duas tabelas fato que compartilham as
dimensões `dim_data` e `dim_cwe`. As duas fatos têm grãos diferentes e por isso não foram fundidas:

| Tabela fato | Grão | Por que existe |
|---|---|---|
| `fato_cve` | uma CVE publicada no NVD entre 01/01/2021 e 31/12/2025 (não rejeitada) | É o universo sobre o qual uma equipe precisa decidir o que corrigir: permite comparar exploradas × não exploradas (P1 a P4, P6) |
| `fato_kev` | uma entrada do catálogo KEV (catálogo completo, 2021-11-03 em diante) | Contém fornecedor/produto e ransomware, que só existem para CVEs exploradas, inclusive as publicadas antes de 2021 (P5) |

`dim_data` é uma dimensão com múltiplos papéis (*role-playing*): data de publicação,
data de inclusão no KEV e prazo de correção. `dim_perfil_cvss` é uma dimensão *junk*:
reúne as quatro métricas de explorabilidade do CVSS, que isoladas teriam 2 a 4 valores cada.

```mermaid
erDiagram
    dim_data ||--o{ fato_cve : "sk_data_publicacao"
    dim_data ||--o{ fato_cve : "sk_data_inclusao_kev"
    dim_cwe ||--o{ fato_cve : "sk_cwe"
    dim_perfil_cvss ||--o{ fato_cve : "sk_perfil_cvss"
    dim_data ||--o{ fato_kev : "sk_data_inclusao"
    dim_data ||--o{ fato_kev : "sk_data_prazo"
    dim_cwe ||--o{ fato_kev : "sk_cwe"
    dim_produto ||--o{ fato_kev : "sk_produto"

    fato_cve {
        string cve_id "chave degenerada"
        int sk_data_publicacao FK
        int sk_cwe FK
        int sk_perfil_cvss FK
        string cvss_versao
        double cvss_score
        string faixa_cvss
        double epss
        double epss_percentil
        double epss_2025_01_01
        double epss_percentil_2025_01_01
        boolean em_kev
        int sk_data_inclusao_kev FK
        int dias_ate_kev
        boolean ransomware_conhecido
    }
    fato_kev {
        string cve_id "chave degenerada"
        int sk_produto FK
        int sk_data_inclusao FK
        int sk_data_prazo FK
        int sk_cwe FK
        boolean ransomware_conhecido
        int prazo_dias
        double epss
        double epss_percentil
        boolean na_populacao_nvd
    }
    dim_data {
        int sk_data PK "AAAAMMDD"
        date data
        int ano
        int trimestre
        int mes
        int dia_semana
    }
    dim_cwe {
        int sk_cwe PK
        string cwe_id
        string nome_cwe
        string abstracao
    }
    dim_perfil_cvss {
        int sk_perfil_cvss PK
        string vetor_ataque
        string complexidade
        string privilegios
        string interacao_usuario
    }
    dim_produto {
        int sk_produto PK
        string fornecedor
        string produto
    }
```

### Decisões de modelagem

* **Uma CWE por CVE.** 17,7% das CVEs da população têm mais de uma CWE. Uma tabela ponte
  (CVE × CWE) seria mais fiel, mas duplicaria contagens nas análises por CWE; optou-se por
  uma CWE principal (regra R7) e a lista completa permanece em `prata_nvd.cwes`.
* **Fornecedor/produto só para o KEV.** O NVD informa produtos por meio de CPEs, que
  exigiriam um tratamento de conciliação à parte. Como a pergunta P5 é sobre o que foi
  explorado, o fornecedor do KEV é suficiente e já vem padronizado pela CISA.
* **Chaves substitutas** (`sk_*`) inteiras nas dimensões; `sk_data` no formato `AAAAMMDD`
  para leitura direta. Chaves primárias e estrangeiras são registradas no Unity Catalog como
  restrições informativas (notebook 04).

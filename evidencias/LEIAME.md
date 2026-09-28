# Evidências da execução na nuvem (Databricks)

Capturas de tela que comprovam a execução do pipeline no Databricks Free Edition.
Cada imagem é referenciada no README, no ponto em que sustenta a afirmação.

| Arquivo | O que mostra | Onde obter |
|---|---|---|
| `01_git_folder.png` | Repositório clonado no Databricks como *Git folder* | Workspace → pasta do repositório |
| `02_volume_brutos.png` | Arquivos brutos persistidos no Volume `/Volumes/workspace/mvp_vuln/brutos` | Catalog → workspace → mvp_vuln → Volumes → brutos |
| `03_job_execucao.png` | Execução bem-sucedida do job com as 6 tarefas encadeadas | Jobs & Pipelines → mvp_priorizacao_vulnerabilidades → Runs (visão de grafo) |
| `04_tabelas_esquema.png` | Tabelas bronze, prata e ouro criadas no esquema `mvp_vuln` | Catalog → workspace → mvp_vuln → Tables |
| `05_catalogo_fato_cve.png` | Comentários de colunas (catálogo) e chaves de `fato_cve` no Unity Catalog | Catalog → fato_cve → aba Overview |
| `06_qualidade.png` | Tabela `qualidade_relatorio` exibida no notebook 05 | Notebook 05, saída da primeira célula |
| `07_p1.png` a `12_p6.png` | Resultado de cada consulta de análise (P1 a P6) no notebook 06 | Notebook 06, saída de cada célula |
| `13_curva_prospectiva.png` | Gráfico esforço × cobertura gerado no Databricks | Notebook 06, célula Python após P3 |

Dica: após executar, exporte os notebooks com as saídas (File → Export → IPython Notebook)
e salve-os em `notebooks/exportados/` — ficam legíveis no GitHub com todos os resultados.

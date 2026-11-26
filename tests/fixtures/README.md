# Тестовые отчёты

| Файл | Откуда |
|---|---|
| `bandit.json` | настоящий вывод `bandit -r -f json` по `examples/vulnerable-app` |
| `pip-audit.json` | настоящий вывод `pip-audit -r requirements.txt -f json` по тому же примеру |
| `semgrep.json` | настоящий вывод `semgrep scan --config .semgrep/python-security.yml --json` |
| `trivy.json` | собран вручную в формате Trivy SchemaVersion 2 (в среде разработки бинарник Trivy был недоступен). Секрет в нём синтетический и замаскирован так же, как его маскирует сам Trivy, — настоящего значения нет. В CI Trivy запускается по-настоящему. |
| `sarif-schema-2.1.0.json` | официальная схема SARIF 2.1.0 из репозитория OASIS `oasis-tcs/sarif-spec` |

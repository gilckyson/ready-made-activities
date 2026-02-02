# Charlas🧾

Arquivos incluídos (apenas estes 4):
- `docker-compose.yml` — roda container com Python e instala dependências na inicialização
- `app.py` — aplicação FastAPI com models SQLAlchemy, seed embutido e endpoints mínimos
- `pyproject.toml` — dependências e script para `uvicorn`
- `README.md` — este arquivo

Resumo do que está implementado:
- Seed automático na inicialização do app (se o banco estiver vazio) usando Faker — cria turmas, alunos (senha padrão: `password`), professores, disciplinas, tarefas. ✅
- Autenticação com JWT via endpoint `/token` (use `username` = aluno email, `password` = `password`). 🔐
- Endpoints protegidos que retornam os dados semeados: `/alunos`, `/professores`, `/disciplinas`, `/tarefas` (necessário Bearer token). ✅
- Banco: SQLite `./database.db` (arquivo criado no container). 🗄️

Como executar (Docker, sem Dockerfile extra):

1. Suba o serviço:

   docker compose up

   O `docker-compose.yml` usa a imagem `python:3.11-slim`, instala dependências no start e executa `uvicorn app:app`.

2. Pegue um token (exemplo com curl):

   curl -X POST -F 'username=aluno1@example.com' -F 'password=password' http://localhost:8000/token

   Use o `access_token` retornado como `Authorization: Bearer <token>` para acessar `/alunos`, `/disciplinas`, etc.

3. Documentação: abra `http://localhost:8000/docs`

Notas:
- Este repositório foi mantido com apenas os quatro arquivos que você pediu.
- Se preferir, posso mudar a estratégia de instalação no `docker-compose` para usar um build + Dockerfile, mas você pediu para não criar mais arquivos.

---


Quer que eu reduza ainda mais os endpoints ou adicione um exemplo pronto de curl para listar `alunos` com token? Responda com sim/não.

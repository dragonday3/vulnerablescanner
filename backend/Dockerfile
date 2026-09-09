FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt requirements-dev.txt ./
# Dev/CI tooling (pytest, ruff, black, mypy, httpx) is installed alongside
# runtime deps so `docker compose exec backend pytest -v` etc. keep working
# unchanged (Task 9's established pattern runs checks inside this
# container) — see requirements-dev.txt for why the files are still split.
RUN pip install --no-cache-dir -r requirements.txt -r requirements-dev.txt
COPY . .
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]

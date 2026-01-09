FROM python:3.12
WORKDIR app
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/
COPY pyproject.toml uv.lock ./
COPY server/pyproject.toml ./server/
RUN uv sync --frozen --no-install-project --package server
COPY shared/ ./shared
COPY server/ ./server
EXPOSE 3045
CMD ["uv", "run", "python3", "-m", "server/app.py"]
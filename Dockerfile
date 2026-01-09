FROM python:3.12
WORKDIR app
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-install-project
COPY shared/ ./shared
COPY server/ ./server
RUN mv server/.env.example server/.env
EXPOSE 3045
CMD ["uv", "run", "server/app.py"]
FROM python:3.12
WORKDIR /app
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/
COPY pyproject.toml uv.lock ./
COPY server/pyproject.toml ./server/
RUN uv sync --frozen --no-install-project --package server
ENV PATH="/app/.venv/bin:$PATH"
COPY shared/ ./shared
COPY server/ ./server
ENV FLASK_ENV=production
ENV PYTHONUNBUFFERED=1
EXPOSE 5000
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "server.app:app"]
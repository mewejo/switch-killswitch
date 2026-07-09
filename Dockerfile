FROM python:3.13-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ app/
COPY tools/ tools/

RUN useradd --system --create-home --uid 10001 killswitch
USER killswitch
# Writable HOME regardless of the uid the container is run as (compose
# overrides `user:` to match the owner of the bind-mounted secrets)
ENV HOME=/tmp

# Configured entirely from environment variables by default (see .env.example);
# pass `--config <path>` with a mounted file to use YAML instead.
ENTRYPOINT ["python", "-m", "app.main"]
CMD []

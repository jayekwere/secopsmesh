FROM node:24-trixie-slim@sha256:0820eaa85e07d0490446dd01d14707e17e6108a36988cf374899cd057eb3812d AS console
WORKDIR /build
COPY frontend/package*.json ./
RUN npm ci --ignore-scripts
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS python-build
WORKDIR /build
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
COPY requirements.runtime.lock ./
RUN pip install --no-cache-dir pip==26.2 && pip install --no-cache-dir -r requirements.runtime.lock
COPY pyproject.toml ./
COPY src/ ./src/
RUN pip install --no-cache-dir --no-deps .

FROM python:3.12-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
LABEL org.opencontainers.image.source="https://github.com/jayekwere/secopsmesh" org.opencontainers.image.licenses="Apache-2.0"
ENV PATH="/opt/venv/bin:$PATH" PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY --from=python-build /opt/venv /opt/venv
# Remove the unused system installer, which is not on the runtime PATH.
RUN rm -rf /usr/local/lib/python3.12/site-packages/pip* /usr/local/bin/pip* && groupadd -g 10001 mesh && useradd -u 10001 -g mesh -M -s /usr/sbin/nologin mesh && mkdir .runtime && chown 10001:10001 .runtime
COPY detections/ ./detections/
COPY --from=console /build/dist/ ./frontend/dist/
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --start-period=20s CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=2)"]
ENTRYPOINT ["secopsmesh"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8080"]

FROM public.ecr.aws/gravitational/teleport-distroless:18.11.8 AS teleport
FROM python:3.15-slim
COPY --from=teleport /usr/local/bin/tctl /usr/local/bin/tctl

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py

CMD ["python", "/app/app.py"]

FROM python:3.13-alpine

# eMudhra: refresh both the CA sources and the generated bundle.
RUN apk add --no-cache --upgrade ca-certificates ca-certificates-bundle \
    && update-ca-certificates
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    QOW_CONFIG_DIR=/config
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
VOLUME ["/config"]
EXPOSE 8080
CMD ["python", "-m", "app.main"]

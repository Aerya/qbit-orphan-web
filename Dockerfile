FROM python:3.13-alpine
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

FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .

RUN python -m pip install -r requirements.txt

COPY . .

RUN adduser --disabled-password --gecos "" sentinel
RUN chown -R sentinel:sentinel /app

USER sentinel

CMD ["python", "src/main.py"]

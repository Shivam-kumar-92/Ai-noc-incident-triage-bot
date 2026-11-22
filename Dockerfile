FROM python:3.12-alpine

WORKDIR /app
COPY . /app
RUN mkdir -p /app/data

EXPOSE 8085

ENTRYPOINT ["python3", "triage_bot.py", "--demo", "--dashboard", "--dashboard-port", "8085"]

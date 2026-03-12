FROM python:3.11-slim

WORKDIR /app

COPY server.py responses.py ./

EXPOSE 4000

CMD ["python", "server.py", "--port", "4000"]

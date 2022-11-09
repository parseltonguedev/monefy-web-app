# syntax=docker/dockerfile:1

FROM python:3.10-slim-buster
WORKDIR /app

EXPOSE 8000

COPY . .
RUN python -m venv env
RUN . env/bin/activate
RUN pip install -r requirements.txt

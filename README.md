# HRS Security Incident Tracker

Минимальное WEB-приложение для демонстрации связки:

nginx -> Flask -> PostgreSQL

## Возможности

- Проверка подключения к PostgreSQL
- Вывод инцидентов из БД
- Добавление новых инцидентов через WEB-форму
- Health-check endpoint

## Структура проекта

hrs-web-app/
├── app.py
├── requirements.txt
├── .env.example
├── templates/
│   └── index.html
├── sql/
│   └── init.sql
└── README.md

## Настройка

Создать .env:

cp .env.example .env

## Установка зависимостей

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt

## Инициализация БД

PGPASSWORD='qwerty!' psql \
-h 127.0.0.1 \
-U hrs_web_user \
-d hrs_database \
-f sql/init.sql

## Запуск приложения

python app.py

Приложение будет доступно:

http://127.0.0.1:8000

## Проверка health-check

curl http://127.0.0.1:8000/health


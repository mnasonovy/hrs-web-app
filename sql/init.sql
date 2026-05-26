CREATE TABLE IF NOT EXISTS incidents (
    id SERIAL PRIMARY KEY,
    title VARCHAR(180) NOT NULL,
    severity VARCHAR(30) NOT NULL DEFAULT 'средняя',
    status VARCHAR(30) NOT NULL DEFAULT 'открыт',
    category VARCHAR(80) DEFAULT 'Сетевые атаки',
    source_ip VARCHAR(45),
    asset VARCHAR(120) DEFAULT 'HRS-WEB',
    assignee VARCHAR(80) DEFAULT 'HRS SOC',
    description TEXT,
    recommendation TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

ALTER TABLE incidents ADD COLUMN IF NOT EXISTS category VARCHAR(80) DEFAULT 'Сетевые атаки';
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS asset VARCHAR(120) DEFAULT 'HRS-WEB';
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS description TEXT;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS recommendation TEXT;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS source_ip VARCHAR(45);
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS assignee VARCHAR(80) DEFAULT 'HRS SOC';
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;

TRUNCATE TABLE incidents RESTART IDENTITY;

WITH seed AS (
    SELECT
        gs AS n,

        CASE gs % 20
            WHEN 0 THEN 'Массовый подбор паролей по SSH'
            WHEN 1 THEN 'Сканирование портов DMZ-сегмента'
            WHEN 2 THEN 'Попытка SQL-инъекции в WEB-форме'
            WHEN 3 THEN 'Подозрительный вход в административную панель'
            WHEN 4 THEN 'Аномальный DNS-трафик от внутреннего узла'
            WHEN 5 THEN 'Обнаружена активность brute-force'
            WHEN 6 THEN 'Попытка доступа к PostgreSQL извне'
            WHEN 7 THEN 'Подозрительный PowerShell-запуск'
            WHEN 8 THEN 'Высокое количество HTTP 404-запросов'
            WHEN 9 THEN 'Попытка обхода авторизации'
            WHEN 10 THEN 'Подозрительный User-Agent в HTTP-запросах'
            WHEN 11 THEN 'Срабатывание Fail2Ban по SSH'
            WHEN 12 THEN 'Подозрительная активность в Tailscale-сегменте'
            WHEN 13 THEN 'Попытка обращения к закрытому порту'
            WHEN 14 THEN 'Подозрительный ICMP-трафик'
            WHEN 15 THEN 'Сканирование WEB-директории'
            WHEN 16 THEN 'Попытка доступа к служебному файлу'
            WHEN 17 THEN 'Аномальная активность пользователя'
            WHEN 18 THEN 'Сетевой шум от неизвестного источника'
            ELSE 'Подозрительный запрос к API'
        END AS base_title,

        CASE gs % 4
            WHEN 0 THEN 'низкая'
            WHEN 1 THEN 'средняя'
            WHEN 2 THEN 'высокая'
            ELSE 'критическая'
        END AS severity,

        CASE gs % 5
            WHEN 0 THEN 'закрыт'
            WHEN 1 THEN 'открыт'
            WHEN 2 THEN 'в работе'
            WHEN 3 THEN 'открыт'
            ELSE 'в работе'
        END AS status,

        CASE gs % 8
            WHEN 0 THEN 'Аутентификация'
            WHEN 1 THEN 'Сетевые атаки'
            WHEN 2 THEN 'WEB-угрозы'
            WHEN 3 THEN 'База данных'
            WHEN 4 THEN 'DMZ'
            WHEN 5 THEN 'NGFW'
            WHEN 6 THEN 'Fail2Ban'
            ELSE 'Мониторинг'
        END AS category,

        CASE gs % 7
            WHEN 0 THEN 'HRS-WEB'
            WHEN 1 THEN 'HRS-DB'
            WHEN 2 THEN 'OPNsense NGFW'
            WHEN 3 THEN 'AD DC'
            WHEN 4 THEN 'Tailscale TS_DMZ'
            WHEN 5 THEN 'nginx reverse proxy'
            ELSE 'PostgreSQL'
        END AS asset,

        CASE gs % 6
            WHEN 0 THEN 'HRS SOC'
            WHEN 1 THEN 'SOC Analyst'
            WHEN 2 THEN 'Security Admin'
            WHEN 3 THEN 'Network Engineer'
            WHEN 4 THEN 'Incident Responder'
            ELSE 'Blue Team'
        END AS assignee,

        '10.' || ((gs * 7) % 255)::text || '.' || ((gs * 13) % 255)::text || '.' || ((gs * 19) % 255)::text AS source_ip,

        NOW() - (gs || ' hours')::interval AS created_at
    FROM generate_series(1, 100) AS gs
)
INSERT INTO incidents (
    title,
    severity,
    status,
    category,
    source_ip,
    asset,
    assignee,
    description,
    recommendation,
    created_at,
    updated_at
)
SELECT
    base_title || ' #' || LPAD(n::text, 3, '0') AS title,
    severity,
    status,
    category,
    source_ip,
    asset,
    assignee,
    'Система мониторинга HRS SOC зафиксировала событие: "' || base_title ||
    '". Источник активности: ' || source_ip ||
    '. Затронутый актив: ' || asset ||
    '. Инцидент требует проверки журналов, правил NGFW и состояния связанных сервисов.' AS description,
    CASE severity
        WHEN 'критическая' THEN 'Немедленно изолировать источник, проверить логи NGFW, Fail2Ban и nginx, затем зафиксировать результат расследования.'
        WHEN 'высокая' THEN 'Провести анализ журналов, проверить повторяемость события и при необходимости усилить правила фильтрации.'
        WHEN 'средняя' THEN 'Проверить контекст события, сопоставить с сетевыми логами и оставить инцидент под наблюдением.'
        ELSE 'Зарегистрировать событие, выполнить базовую проверку и закрыть при отсутствии повторений.'
    END AS recommendation,
    created_at,
    created_at + ((n % 8) || ' minutes')::interval
FROM seed;

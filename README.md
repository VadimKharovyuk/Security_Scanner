# WebCraft AI Security Scanner

Платформа автоматизированного анализа безопасности веб-приложений: обнаружение уязвимостей, построение сценариев атаки и **техническое подтверждение** их реального воздействия.

Главная задача — не просто найти потенциальную уязвимость, а установить, насколько далеко злоумышленник может продвинуться от публичного веб-интерфейса к внутренним ресурсам и базе данных.

---

## Содержание

- [Ключевая идея](#ключевая-идея)
- [Принципы](#принципы)
- [Текущий статус](#текущий-статус)
- [Технологический стек](#технологический-стек)
- [Структура проекта](#структура-проекта)
- [Запуск](#запуск)
- [Конфигурация](#конфигурация)
- [База данных](#база-данных)
- [REST API](#rest-api)
- [Roadmap](#roadmap)
- [Безопасность и правовые ограничения](#безопасность-и-правовые-ограничения)

---

## Ключевая идея

Обычный сканер отвечает на вопрос «какие уязвимости есть?». Этот проект отвечает на вопросы:

- какие из обнаруженных уязвимостей действительно эксплуатируемы;
- можно ли через них получить доступ к данным приложения;
- можно ли прочитать данные из БД через уязвимый путь;
- какие операции доступны: `READ`, `WRITE` или `ADMIN`;
- какие переходы подтверждены техническими доказательствами, а какие остаются теоретическими;
- какой реальный риск представляет обнаруженная цепочка.

**Ключевое отличие:** заключения AI без технических доказательств не считаются подтверждением уязвимости.

---

## Принципы

### 1. Evidence-Based Security Analysis

Каждая подтверждённая уязвимость имеет техническое доказательство: тип проверки, актив и URL, время, инструмент и версию, правило проверки, HTTP-метаданные, идентификаторы доказательств, результат валидации, уверенность и ограничения.

### 2. Detected → Validated → Impact Confirmed

Три раздельных состояния. Теоретический сценарий не переводится в подтверждённый автоматически.

### 3. Разделение доступа

- **Application-Mediated Database Access** — доступ к БД через уязвимость приложения и его существующее подключение.
- **Direct Database Network Access** — прямой сетевой доступ к серверу БД.
- **Infrastructure Access** — доступ к другим внутренним ресурсам.

Успешная SQL Injection не означает прямой сетевой доступ к PostgreSQL. Каждый тип проверяется отдельно.

---

## Текущий статус

Проект в начале разработки. Реализовано:

- [x] Каркас Spring Boot приложения
- [x] Подключение к PostgreSQL
- [x] Домашняя страница (Thymeleaf, без CSS)
- [x] Базовые enum'ы доменной модели
- [ ] Сущности `Project` и `Asset`
- [ ] `AssetScopeService`
- [ ] Scan Orchestrator и сканеры
- [ ] Finding Processor и Evidence Manager
- [ ] AI-слой
- [ ] Attack Graph
- [ ] Validation Engine
- [ ] Database Access Validation
- [ ] Отчёты

### Реализованные enum'ы

| Enum | Назначение |
|---|---|
| `ScanStatus` | Жизненный цикл сканирования |
| `ScanTaskStatus` | Статус отдельной задачи |
| `ScannerType` | Тип сканера |
| `FindingStatus` | Статус уязвимости |
| `Severity` | Критичность |
| `Confidence` | Уверенность |
| `AttackPathEdgeStatus` | Статус перехода в графе атак |
| `AccessType` | Тип доступа |
| `AccessCapability` | Подтверждённые возможности (`READ`/`WRITE`/`EXECUTE`/`ADMIN`) |
| `AiTaskType` | Тип задачи для AI-роутера |
| `ValidationMode` | Режим проверки |
| `ReportFormat` | Формат отчёта |

---

## Технологический стек

**Backend**

- Java 21
- Spring Boot 4.1.2
- Spring Web MVC
- Spring Data JPA / Hibernate
- PostgreSQL
- Lombok
- Thymeleaf

**Frontend**

- Thymeleaf
- HTML
- JavaScript
- CSS *(пока не используется)*

**Планируется**

- Spring Security (позже)
- Spring AI: Ollama + cloud LLM через OpenAI-compatible API
- OWASP ZAP, HTTP Scanner, TLS Scanner
- Docker для изоляции scanner workers (в конце проекта)
- Redis, Flyway — **не используются**

---

## Структура проекта

```
src/main/java/Security_Scanner/Security_Scanner/
├── config/        # конфигурация Spring
├── controller/    # MVC-контроллеры
├── dto/           # request/response модели
├── enums/         # доменные перечисления
├── exception/     # обработка ошибок
├── mapper/        # ручные мапперы (без MapStruct)
├── model/         # JPA-сущности
├── repository/    # Spring Data репозитории
└── service/       # бизнес-логика
```

```
src/main/resources/
├── static/        # статические ресурсы
├── templates/     # Thymeleaf-шаблоны
└── application.properties
```

---

## Запуск

### Требования

- JDK 21+
- PostgreSQL 15+
- Maven Wrapper (входит в проект)

### 1. Создать базу данных

```sql
CREATE DATABASE "Security_Scanner";
```

### 2. Настроить подключение

Параметры по умолчанию — в `src/main/resources/application.properties`. Переопределяются переменными окружения:

```bash
export DB_URL="jdbc:postgresql://localhost:5432/Security_Scanner"
export DB_USERNAME="postgres"
export DB_PASSWORD="ваш_пароль"
```

### 3. Запустить

```bash
./mvnw spring-boot:run
```

Приложение будет доступно на **http://localhost:2157/**.

### Сборка

```bash
./mvnw clean package
java -jar target/Security_Scanner-0.0.1-SNAPSHOT.jar
```

---

## Конфигурация

```properties
spring.application.name=Security_Scanner
server.port=2157

# PostgreSQL
spring.datasource.driver-class-name=org.postgresql.Driver
spring.datasource.url=${DB_URL:jdbc:postgresql://localhost:5432/Security_Scanner}
spring.datasource.username=${DB_USERNAME:postgres}
spring.datasource.password=${DB_PASSWORD:19111993}

# JPA / Hibernate
spring.jpa.hibernate.ddl-auto=update
spring.jpa.show-sql=false
spring.jpa.open-in-view=false
spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.PostgreSQLDialect
spring.jpa.properties.hibernate.format_sql=true
```

> ⚠️ `ddl-auto=update` используется только для разработки. Перед production схему нужно зафиксировать (`validate`) и перейти на управляемые миграции.

> ⚠️ Пароль по умолчанию задан в файле. Для реального использования вынесите его в переменную окружения и уберите значение по умолчанию.

> ℹ️ `hibernate.dialect` указан явно, хотя Hibernate 6+ определяет диалект автоматически и пишет об этом WARN. Строку можно удалить.

---

## База данных

- СУБД: **PostgreSQL**
- База: `Security_Scanner`
- Миграции: **Flyway не используется** — схема управляется Hibernate (`ddl-auto=update`)
- Таблицы создаются автоматически по JPA-сущностям

### Планируемые сущности

**Core:** `Project`, `Asset`, `ScanProfile`, `Scan`, `ScanTask`, `ScanEvent`, `ScannerExecution`, `Finding`, `ScanFinding`, `VulnerabilityReference`

**Attack Graph:** `AttackPath`, `AttackPathNode`, `AttackPathEdge`, `ValidationRun`

**Database Access:** `ValidationAttempt`, `DatabaseAccessEvidence`, `CanaryRecord`, `AccessCapability`

**Evidence:** `SecurityEvidence`

**AI:** `AIAnalysis`, `AIExecution`, `PromptVersion`

**Report:** `Report`, `ReportSection`

---

## REST API

Планируемые эндпоинты:

| Метод | Путь | Назначение |
|---|---|---|
| `POST` | `/api/projects` | Создать проект |
| `GET` | `/api/projects` | Список проектов |
| `GET` | `/api/projects/{id}` | Проект по ID |
| `POST` | `/api/assets` | Добавить актив |
| `GET` | `/api/assets` | Список активов |
| `GET` | `/api/assets/{id}` | Актив по ID |
| `DELETE` | `/api/assets/{id}` | Удалить актив |
| `POST` | `/api/scans` | Запустить сканирование |
| `GET` | `/api/scans` | Список сканирований |
| `GET` | `/api/scans/{id}` | Сканирование по ID |
| `POST` | `/api/scans/{id}/cancel` | Отменить сканирование |
| `GET` | `/api/findings` | Список находок |
| `GET` | `/api/findings/{id}` | Находка по ID |
| `GET` | `/api/attack-paths` | Список цепочек атак |
| `GET` | `/api/attack-paths/{id}` | Цепочка по ID |
| `GET` | `/api/validations` | Список проверок |
| `GET` | `/api/validations/{id}` | Проверка по ID |
| `GET` | `/api/database-access` | Результаты доступа к БД |
| `GET` | `/api/database-access/{id}` | Результат по ID |
| `GET` | `/api/reports/{scanId}` | Отчёт по сканированию |

---

## Roadmap

| Этап | Содержание |
|---|---|
| 1 | Каркас проекта, PostgreSQL, `Project`, `Asset`, `AssetScopeService` |
| 2 | HTTP Scanner, TLS Scanner, OWASP ZAP, Scan Orchestrator |
| 3 | Finding Processor, Evidence Manager |
| 4 | AI Provider Router, Ollama + Cloud LLM, валидация ответов |
| 5 | Attack Graph Engine |
| 6 | Database Access Validation Engine, Canary Records, `READ`/`WRITE`/`ADMIN` |
| 7 | Report Engine (HTML / PDF / JSON) |
| 8 | Hardening: SSRF, DNS rebinding, изоляция workers, audit logging |
| 9 | Docker-изоляция scanner workers |

---

## Безопасность и правовые ограничения

Платформа сканирует только те ресурсы, на которые у пользователя есть явное разрешение.

**Обязательные технические ограничения:**

- проверка `allowed-hosts` перед **каждым** сетевым соединением;
- блокировка `localhost`, private/link-local IP, cloud metadata endpoints;
- защита от SSRF и DNS rebinding;
- запрет редиректов за пределы разрешённой области;
- таймауты, лимиты размера ответов и числа запросов;
- редактирование секретов и персональных данных перед сохранением и передачей в LLM;
- AI не имеет произвольного доступа к shell, SSH, production DB и секретам;
- AI не может самостоятельно перевести Finding в `CONFIRMED` или объявить `READ`/`WRITE`/`ADMIN` без технических доказательств;
- запрещены разрушительные операции и массовое извлечение пользовательских данных.

**MVP не включает:** автоматическое исправление уязвимостей, изменение production-конфигурации, постоянный SSH/root-доступ, постоянные привилегированные DB credentials, массовое сканирование произвольных доменов, анализ исходного кода.

---

## Лицензия

Не указана.

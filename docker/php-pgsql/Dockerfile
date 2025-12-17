FROM php:8.2-cli

RUN apt-get update \
    && apt-get install -y --no-install-recommends libpq-dev \
    && docker-php-ext-install pgsql \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tests

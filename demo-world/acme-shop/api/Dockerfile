FROM php:8.1.2-apache
COPY . /var/www/html/
RUN docker-php-ext-install pdo pdo_pgsql
EXPOSE 80

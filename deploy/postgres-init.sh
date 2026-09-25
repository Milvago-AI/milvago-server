#!/bin/sh
set -eu
psql -v ON_ERROR_STOP=1 --username postgres --dbname postgres \
  --set=runtime_password="$RUNTIME_PASSWORD" \
  --set=migration_password="$MIGRATION_PASSWORD" \
  --set=identity_password="$IDENTITY_DB_PASSWORD" <<'SQL'
CREATE ROLE milvago_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD :'runtime_password';
CREATE ROLE milvago_migration LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD :'migration_password';
CREATE ROLE milvago_lookup NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
GRANT milvago_lookup TO milvago_migration;
CREATE ROLE milvago_identity LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD :'identity_password';
CREATE DATABASE milvago OWNER milvago_migration;
CREATE DATABASE milvago_identity OWNER milvago_identity;
REVOKE ALL ON DATABASE milvago FROM PUBLIC;
REVOKE ALL ON DATABASE milvago_identity FROM PUBLIC;
GRANT CONNECT ON DATABASE milvago TO milvago_runtime;
SQL
psql -v ON_ERROR_STOP=1 --username postgres --dbname milvago <<'SQL'
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO milvago_runtime;
SQL

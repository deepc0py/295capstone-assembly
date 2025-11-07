-- Create VentiAPI Database for Scan History
-- This runs automatically when PostgreSQL container starts
-- PostgreSQL version: 16+ (pgvector/pgvector:pg16)

-- Create the ventiapi database if it doesn't exist
-- Note: We use rag_user (from docker-compose.yml) as the owner
SELECT 'CREATE DATABASE ventiapi OWNER rag_user ENCODING UTF8'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'ventiapi')\gexec

-- Grant all privileges to rag_user
GRANT ALL PRIVILEGES ON DATABASE ventiapi TO rag_user;

-- Note: The actual schema (tables, indexes, etc.) is in 002_scan_history.sql
-- That file will be executed against the ventiapi database

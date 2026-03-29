"""
Repair migration: creates tables that were recorded as applied in django_migrations
but never physically created in the database.

Tables created (all use IF NOT EXISTS so safe to re-apply):
  - api_otpverification
  - api_organizationquestionnaire
  - api_scantoken
  - api_scan
"""

from django.db import migrations


SQL_CREATE_OTPVERIFICATION = """
CREATE TABLE IF NOT EXISTS api_otpverification (
    id          bigserial    PRIMARY KEY,
    email       varchar(254) NOT NULL,
    otp_code    varchar(6)   NOT NULL,
    purpose     varchar(20)  NOT NULL,
    created_at  timestamptz  NOT NULL DEFAULT now(),
    expires_at  timestamptz  NOT NULL,
    is_verified boolean      NOT NULL DEFAULT false
);
"""

SQL_CREATE_OTPVERIFICATION_INDEX = """
CREATE INDEX IF NOT EXISTS api_otpveri_email_7e6940_idx
    ON api_otpverification (email, otp_code, purpose);
"""

SQL_CREATE_ORGANIZATIONQUESTIONNAIRE = """
CREATE TABLE IF NOT EXISTS api_organizationquestionnaire (
    id                      bigserial PRIMARY KEY,
    ip_address              inet      NOT NULL,
    has_security_policy     boolean   NOT NULL DEFAULT false,
    conducts_regular_audits boolean   NOT NULL DEFAULT false,
    has_incident_response   boolean   NOT NULL DEFAULT false,
    uses_encryption         boolean   NOT NULL DEFAULT false,
    completed_at            timestamptz NOT NULL DEFAULT now(),
    organization_id         uuid      NOT NULL,
    CONSTRAINT api_organizationquestionnaire_organization_id_key
        UNIQUE (organization_id),
    CONSTRAINT api_organizationquestionnaire_organization_id_fk
        FOREIGN KEY (organization_id)
        REFERENCES api_organization(organization_id)
        ON DELETE CASCADE
        DEFERRABLE INITIALLY DEFERRED
);
"""

SQL_CREATE_SCANTOKEN = """
CREATE TABLE IF NOT EXISTS api_scantoken (
    token           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at      timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL,
    is_used         boolean     NOT NULL DEFAULT false,
    used_at         timestamptz,
    organization_id uuid        NOT NULL,
    user_id         bigint      NOT NULL,
    CONSTRAINT api_scantoken_organization_id_fk
        FOREIGN KEY (organization_id)
        REFERENCES api_organization(organization_id)
        ON DELETE CASCADE
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT api_scantoken_user_id_fk
        FOREIGN KEY (user_id)
        REFERENCES api_user(id)
        ON DELETE CASCADE
        DEFERRABLE INITIALLY DEFERRED
);
"""

SQL_CREATE_SCANTOKEN_INDEXES = """
CREATE INDEX IF NOT EXISTS api_scantoken_organization_id_idx
    ON api_scantoken (organization_id);
CREATE INDEX IF NOT EXISTS api_scantoken_user_id_idx
    ON api_scantoken (user_id);
"""

SQL_CREATE_SCAN = """
CREATE TABLE IF NOT EXISTS api_scan (
    id                      uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    status                  varchar(20) NOT NULL DEFAULT 'PENDING',
    error_message           text,
    report_task_id          varchar(255),
    created_at              timestamptz NOT NULL DEFAULT now(),
    scan_started_at         timestamptz,
    scan_completed_at       timestamptz,
    report_completed_at     timestamptz,
    scan_duration_seconds   integer,
    target_subnet           text,
    scanner_version         varchar(20),
    groups_completed        smallint    NOT NULL DEFAULT 0,
    skipped_tools           jsonb       NOT NULL DEFAULT '[]',
    raw_findings_json       text,
    finding_count_critical  smallint    NOT NULL DEFAULT 0,
    finding_count_high      smallint    NOT NULL DEFAULT 0,
    finding_count_medium    smallint    NOT NULL DEFAULT 0,
    finding_count_low       smallint    NOT NULL DEFAULT 0,
    finding_count_info      smallint    NOT NULL DEFAULT 0,
    organization_id         uuid        NOT NULL,
    report_id               uuid,
    user_id                 bigint      NOT NULL,
    token_id                uuid,
    CONSTRAINT api_scan_organization_id_fk
        FOREIGN KEY (organization_id)
        REFERENCES api_organization(organization_id)
        ON DELETE CASCADE
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT api_scan_report_id_fk
        FOREIGN KEY (report_id)
        REFERENCES api_report(report_id)
        ON DELETE SET NULL
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT api_scan_user_id_fk
        FOREIGN KEY (user_id)
        REFERENCES api_user(id)
        ON DELETE CASCADE
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT api_scan_token_id_fk
        FOREIGN KEY (token_id)
        REFERENCES api_scantoken(token)
        ON DELETE SET NULL
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT api_scan_report_id_key UNIQUE (report_id),
    CONSTRAINT api_scan_token_id_key  UNIQUE (token_id)
);
"""

SQL_CREATE_SCAN_INDEXES = """
CREATE INDEX IF NOT EXISTS api_scan_status_idx         ON api_scan (status);
CREATE INDEX IF NOT EXISTS api_scan_organization_id_idx ON api_scan (organization_id);
CREATE INDEX IF NOT EXISTS api_scan_user_id_idx         ON api_scan (user_id);
"""


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0017_repair_user_encrypted_columns_to_text'),
    ]

    operations = [
        migrations.RunSQL(
            sql=SQL_CREATE_OTPVERIFICATION,
            reverse_sql="DROP TABLE IF EXISTS api_otpverification;",
        ),
        migrations.RunSQL(
            sql=SQL_CREATE_OTPVERIFICATION_INDEX,
            reverse_sql="DROP INDEX IF EXISTS api_otpveri_email_7e6940_idx;",
        ),
        migrations.RunSQL(
            sql=SQL_CREATE_ORGANIZATIONQUESTIONNAIRE,
            reverse_sql="DROP TABLE IF EXISTS api_organizationquestionnaire;",
        ),
        migrations.RunSQL(
            sql=SQL_CREATE_SCANTOKEN,
            reverse_sql="DROP TABLE IF EXISTS api_scantoken;",
        ),
        migrations.RunSQL(
            sql=SQL_CREATE_SCANTOKEN_INDEXES,
            reverse_sql="""
                DROP INDEX IF EXISTS api_scantoken_organization_id_idx;
                DROP INDEX IF EXISTS api_scantoken_user_id_idx;
            """,
        ),
        migrations.RunSQL(
            sql=SQL_CREATE_SCAN,
            reverse_sql="DROP TABLE IF EXISTS api_scan;",
        ),
        migrations.RunSQL(
            sql=SQL_CREATE_SCAN_INDEXES,
            reverse_sql="""
                DROP INDEX IF EXISTS api_scan_status_idx;
                DROP INDEX IF EXISTS api_scan_organization_id_idx;
                DROP INDEX IF EXISTS api_scan_user_id_idx;
            """,
        ),
    ]

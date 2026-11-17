/*
# SOC Alert Triage Assistant - Database Schema

## Overview
Creates the database tables for an AI-Powered SOC Alert Triage Assistant.
The system ingests raw security alerts, runs them through a triage engine
that scores risk and classifies them, and stores the results for display
on a dashboard.

## New Tables

### alerts
- `id` (uuid, primary key)
- `source` (text) - which tool generated the alert (firewall, antivirus, cloud monitor, etc.)
- `alert_type` (text) - type of alert (failed_login, port_scan, malware_detected, etc.)
- `severity` (text) - original severity from the source tool (info, low, medium, high, critical)
- `raw_log` (text) - the raw log entry text
- `source_ip` (text) - IP address the alert originated from
- `destination_ip` (text) - target IP address
- `username` (text) - related username if applicable
- `hostname` (text) - related hostname
- `timestamp` (timestamptz) - when the original alert event occurred
- `status` (text) - triage status: pending, triaged, acknowledged, resolved
- `created_at` (timestamptz) - when the alert was ingested

### triage_results
- `id` (uuid, primary key)
- `alert_id` (uuid, foreign key to alerts)
- `risk_level` (text) - AI-assigned risk level: low, medium, high, critical
- `risk_score` (integer) - numeric risk score 0-100
- `summary` (text) - plain-English summary of the threat
- `recommendation` (text) - suggested remediation action
- `indicators` (jsonb) - list of suspicious indicators identified
- `is_false_positive` (boolean) - whether the AI classified this as a false positive
- `confidence` (integer) - confidence in the assessment 0-100
- `created_at` (timestamptz)

## Security
- RLS enabled on both tables.
- Single-tenant app (no sign-in) — policies allow anon + authenticated full CRUD
  since this is a shared SOC dashboard prototype.
*/ 

CREATE TABLE IF NOT EXISTS alerts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  source text NOT NULL DEFAULT 'unknown',
  alert_type text NOT NULL DEFAULT 'unknown',
  severity text NOT NULL DEFAULT 'info',
  raw_log text NOT NULL,
  source_ip text,
  destination_ip text,
  username text,
  hostname text,
  "timestamp" timestamptz NOT NULL DEFAULT now(),
  status text NOT NULL DEFAULT 'pending',
  created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE alerts ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "anon_select_alerts" ON alerts;
CREATE POLICY "anon_select_alerts" ON alerts FOR SELECT
  TO anon, authenticated USING (true);

DROP POLICY IF EXISTS "anon_insert_alerts" ON alerts;
CREATE POLICY "anon_insert_alerts" ON alerts FOR INSERT
  TO anon, authenticated WITH CHECK (true);

DROP POLICY IF EXISTS "anon_update_alerts" ON alerts;
CREATE POLICY "anon_update_alerts" ON alerts FOR UPDATE
  TO anon, authenticated USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "anon_delete_alerts" ON alerts;
CREATE POLICY "anon_delete_alerts" ON alerts FOR DELETE
  TO anon, authenticated USING (true);

CREATE TABLE IF NOT EXISTS triage_results (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  alert_id uuid NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
  risk_level text NOT NULL DEFAULT 'low',
  risk_score integer NOT NULL DEFAULT 0,
  summary text NOT NULL DEFAULT '',
  recommendation text NOT NULL DEFAULT '',
  indicators jsonb NOT NULL DEFAULT '[]'::jsonb,
  is_false_positive boolean NOT NULL DEFAULT false,
  confidence integer NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE triage_results ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "anon_select_triage" ON triage_results;
CREATE POLICY "anon_select_triage" ON triage_results FOR SELECT
  TO anon, authenticated USING (true);

DROP POLICY IF EXISTS "anon_insert_triage" ON triage_results;
CREATE POLICY "anon_insert_triage" ON triage_results FOR INSERT
  TO anon, authenticated WITH CHECK (true);

DROP POLICY IF EXISTS "anon_update_triage" ON triage_results;
CREATE POLICY "anon_update_triage" ON triage_results FOR UPDATE
  TO anon, authenticated USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "anon_delete_triage" ON triage_results;
CREATE POLICY "anon_delete_triage" ON triage_results FOR DELETE
  TO anon, authenticated USING (true);

CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts("timestamp" DESC);
CREATE INDEX IF NOT EXISTS idx_triage_alert_id ON triage_results(alert_id);
CREATE INDEX IF NOT EXISTS idx_triage_risk_level ON triage_results(risk_level);

--
-- PostgreSQL database dump
--

\restrict QfLSYGj80L3yDSWT7gXEl1LXAgQaQFD8tfGVTgMHFhxvkQ919OtU1Iuo0FwltQr

-- Dumped from database version 15.18
-- Dumped by pg_dump version 15.18

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: public; Type: SCHEMA; Schema: -; Owner: -
--

-- *not* creating schema, since initdb creates it


--
-- Name: agent_status_enum; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.agent_status_enum AS ENUM (
    'not_enrolled',
    'active',
    'disabled',
    'revoked'
);


--
-- Name: transport_preference_enum; Type: TYPE; Schema: public; Owner: -
--

CREATE TYPE public.transport_preference_enum AS ENUM (
    'auto',
    'ssh',
    'agent'
);


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: access_bindings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.access_bindings (
    id integer NOT NULL,
    subject_user_id integer,
    subject_app_role_id integer,
    scope_group_id integer,
    scope_smart_group_id integer,
    fleet_role_id integer NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    expires_at timestamp without time zone,
    created_by integer,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: access_bindings_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.access_bindings_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: access_bindings_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.access_bindings_id_seq OWNED BY public.access_bindings.id;


--
-- Name: access_grants; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.access_grants (
    id integer NOT NULL,
    user_id integer NOT NULL,
    system_id integer NOT NULL,
    fleet_role_id integer NOT NULL,
    login character varying(100) NOT NULL,
    via_binding_id integer,
    is_implicit_admin boolean DEFAULT false NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL,
    expires_at timestamp without time zone
);


--
-- Name: access_grants_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.access_grants_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: access_grants_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.access_grants_id_seq OWNED BY public.access_grants.id;


--
-- Name: access_requests; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.access_requests (
    id integer NOT NULL,
    requested_by integer NOT NULL,
    fleet_role_id integer NOT NULL,
    scope_group_id integer,
    scope_smart_group_id integer,
    justification text,
    duration_seconds integer DEFAULT 3600 NOT NULL,
    status character varying(20) DEFAULT 'pending'::character varying NOT NULL,
    decided_by integer,
    decided_at timestamp without time zone,
    decision_comment text,
    resulting_binding_id integer,
    requested_at timestamp without time zone DEFAULT now() NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: access_requests_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.access_requests_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: access_requests_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.access_requests_id_seq OWNED BY public.access_requests.id;


--
-- Name: access_review_items; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.access_review_items (
    id integer NOT NULL,
    review_id integer NOT NULL,
    binding_id integer,
    binding_snapshot_json text NOT NULL,
    action character varying(20) DEFAULT 'pending'::character varying NOT NULL,
    decided_at timestamp without time zone,
    decided_by integer,
    notes text,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: access_review_items_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.access_review_items_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: access_review_items_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.access_review_items_id_seq OWNED BY public.access_review_items.id;


--
-- Name: access_reviews; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.access_reviews (
    id integer NOT NULL,
    scope character varying(20) NOT NULL,
    scope_ref_id integer,
    state character varying(20) DEFAULT 'pending'::character varying NOT NULL,
    due_at timestamp without time zone NOT NULL,
    completed_at timestamp without time zone,
    reviewer_id integer,
    summary text,
    created_by integer,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: access_reviews_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.access_reviews_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: access_reviews_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.access_reviews_id_seq OWNED BY public.access_reviews.id;


--
-- Name: activation_token_redemptions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.activation_token_redemptions (
    id integer NOT NULL,
    activation_token_id integer NOT NULL,
    host_fingerprint_hash character varying(64) NOT NULL,
    system_id integer,
    first_redeemed_at timestamp without time zone NOT NULL,
    last_redeemed_at timestamp without time zone NOT NULL,
    redeem_count integer DEFAULT 1 NOT NULL,
    last_seen_hostname character varying(255),
    last_seen_ip inet,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


--
-- Name: activation_token_redemptions_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.activation_token_redemptions_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: activation_token_redemptions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.activation_token_redemptions_id_seq OWNED BY public.activation_token_redemptions.id;


--
-- Name: activation_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.activation_tokens (
    id integer NOT NULL,
    name character varying(255) NOT NULL,
    token_hash character varying(255) NOT NULL,
    token_prefix character varying(16) NOT NULL,
    default_group_id integer NOT NULL,
    default_tag_ids jsonb DEFAULT '[]'::jsonb NOT NULL,
    ttl_expires_at timestamp without time zone NOT NULL,
    max_uses integer NOT NULL,
    uses_count integer DEFAULT 0 NOT NULL,
    revoked_at timestamp without time zone,
    revoked_by_user_id integer,
    created_by_user_id integer NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    target_system_id integer NOT NULL,
    CONSTRAINT activation_tokens_max_uses_positive CHECK ((max_uses >= 1)),
    CONSTRAINT activation_tokens_uses_within_bounds CHECK (((uses_count >= 0) AND (uses_count <= max_uses)))
);


--
-- Name: activation_tokens_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.activation_tokens_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: activation_tokens_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.activation_tokens_id_seq OWNED BY public.activation_tokens.id;


--
-- Name: airgap_bundle_signing_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.airgap_bundle_signing_keys (
    id integer NOT NULL,
    status character varying(20) NOT NULL,
    gpg_fingerprint character varying(64) NOT NULL,
    key_uid character varying(255) NOT NULL,
    vault_path character varying(255) NOT NULL,
    armored_public_key text,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT airgap_bundle_signing_keys_status_valid CHECK (((status)::text = ANY ((ARRAY['active'::character varying, 'rotating_out'::character varying, 'retired'::character varying])::text[])))
);


--
-- Name: airgap_bundle_signing_keys_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.airgap_bundle_signing_keys_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: airgap_bundle_signing_keys_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.airgap_bundle_signing_keys_id_seq OWNED BY public.airgap_bundle_signing_keys.id;


--
-- Name: airgap_bundles; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.airgap_bundles (
    id integer NOT NULL,
    bundle_id character varying(64) NOT NULL,
    kind character varying(16) NOT NULL,
    parent_bundle_id character varying(64),
    status character varying(24) NOT NULL,
    bundle_descriptor_path character varying(512),
    bundle_path character varying(512),
    payload_sha256 character varying(64),
    byte_count bigint,
    signing_key_id integer,
    request_payload text,
    error_text text,
    started_at timestamp without time zone NOT NULL,
    finished_at timestamp without time zone,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT airgap_bundles_kind_valid CHECK (((kind)::text = ANY ((ARRAY['full'::character varying, 'delta'::character varying])::text[]))),
    CONSTRAINT airgap_bundles_parent_matches_kind CHECK (((((kind)::text = 'full'::text) AND (parent_bundle_id IS NULL)) OR (((kind)::text = 'delta'::text) AND (parent_bundle_id IS NOT NULL)))),
    CONSTRAINT airgap_bundles_status_valid CHECK (((status)::text = ANY ((ARRAY['building'::character varying, 'descriptor_ready'::character varying, 'ok'::character varying, 'failed'::character varying])::text[])))
);


--
-- Name: airgap_bundles_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.airgap_bundles_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: airgap_bundles_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.airgap_bundles_id_seq OWNED BY public.airgap_bundles.id;


--
-- Name: airgap_import_trust_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.airgap_import_trust_keys (
    id integer NOT NULL,
    gpg_fingerprint character varying(64) NOT NULL,
    key_uid character varying(255) NOT NULL,
    armored_public_key text NOT NULL,
    added_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    deleted_at timestamp without time zone,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


--
-- Name: airgap_import_trust_keys_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.airgap_import_trust_keys_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: airgap_import_trust_keys_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.airgap_import_trust_keys_id_seq OWNED BY public.airgap_import_trust_keys.id;


--
-- Name: airgap_imports; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.airgap_imports (
    id integer NOT NULL,
    bundle_id character varying(64) NOT NULL,
    parent_bundle_id character varying(64),
    kind character varying(16) NOT NULL,
    status character varying(16) NOT NULL,
    payload_sha256 character varying(64),
    byte_count bigint,
    error_text text,
    started_at timestamp without time zone NOT NULL,
    finished_at timestamp without time zone,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    path character varying(1024),
    target_mirror_slugs jsonb DEFAULT '[]'::jsonb NOT NULL,
    CONSTRAINT airgap_imports_kind_valid CHECK (((kind)::text = ANY ((ARRAY['full'::character varying, 'delta'::character varying])::text[]))),
    CONSTRAINT airgap_imports_status_valid CHECK (((status)::text = ANY ((ARRAY['verifying'::character varying, 'extracting'::character varying, 'ok'::character varying, 'failed'::character varying])::text[])))
);


--
-- Name: airgap_imports_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.airgap_imports_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: airgap_imports_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.airgap_imports_id_seq OWNED BY public.airgap_imports.id;


--
-- Name: alembic_version; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.alembic_version (
    version_num character varying(32) NOT NULL
);


--
-- Name: alert_configs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.alert_configs (
    id integer NOT NULL,
    name character varying(100) NOT NULL,
    alert_type character varying(50) NOT NULL,
    destination text NOT NULL,
    events text NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    created_by integer,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL,
    secret character varying(255),
    scope_smart_group_id integer
);


--
-- Name: alert_configs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.alert_configs_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: alert_configs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.alert_configs_id_seq OWNED BY public.alert_configs.id;


--
-- Name: alert_history; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.alert_history (
    id integer NOT NULL,
    alert_config_id integer NOT NULL,
    event_type character varying(50) NOT NULL,
    message text,
    sent_at timestamp without time zone DEFAULT now() NOT NULL,
    status character varying(20) NOT NULL,
    error_message text,
    response_code integer,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL,
    payload text,
    attempt_count integer DEFAULT 1 NOT NULL,
    next_retry_at timestamp without time zone,
    last_attempted_at timestamp without time zone
);


--
-- Name: alert_history_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.alert_history_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: alert_history_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.alert_history_id_seq OWNED BY public.alert_history.id;


--
-- Name: app_settings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.app_settings (
    id integer NOT NULL,
    setting_key character varying(100) NOT NULL,
    setting_value text NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: app_settings_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.app_settings_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: app_settings_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.app_settings_id_seq OWNED BY public.app_settings.id;


--
-- Name: audit_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.audit_events (
    id integer NOT NULL,
    schema_version integer DEFAULT 1 NOT NULL,
    event_uuid character varying(36) NOT NULL,
    "timestamp" timestamp without time zone DEFAULT now() NOT NULL,
    action character varying(64) NOT NULL,
    outcome character varying(20) DEFAULT 'success'::character varying NOT NULL,
    actor_user_id integer,
    actor_username character varying(200),
    actor_ip character varying(64),
    target_system_id integer,
    target_kind character varying(40),
    target_id character varying(200),
    context_json text,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: audit_events_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.audit_events_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: audit_events_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.audit_events_id_seq OWNED BY public.audit_events.id;


--
-- Name: audit_sink_deliveries; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.audit_sink_deliveries (
    id integer NOT NULL,
    sink_id integer NOT NULL,
    event_id integer NOT NULL,
    status character varying(20) DEFAULT 'pending'::character varying NOT NULL,
    attempts integer DEFAULT 0 NOT NULL,
    last_error text,
    next_attempt_at timestamp without time zone,
    delivered_at timestamp without time zone,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: audit_sink_deliveries_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.audit_sink_deliveries_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: audit_sink_deliveries_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.audit_sink_deliveries_id_seq OWNED BY public.audit_sink_deliveries.id;


--
-- Name: audit_sinks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.audit_sinks (
    id integer NOT NULL,
    name character varying(100) NOT NULL,
    kind character varying(20) NOT NULL,
    target character varying(1024) NOT NULL,
    hmac_secret character varying(256),
    config_json text,
    enabled boolean DEFAULT true NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: audit_sinks_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.audit_sinks_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: audit_sinks_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.audit_sinks_id_seq OWNED BY public.audit_sinks.id;


--
-- Name: baseline_checks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.baseline_checks (
    id integer NOT NULL,
    baseline_id integer NOT NULL,
    system_id integer NOT NULL,
    run_at timestamp without time zone DEFAULT now() NOT NULL,
    status character varying(20) NOT NULL,
    drift_details_json text,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: baseline_checks_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.baseline_checks_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: baseline_checks_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.baseline_checks_id_seq OWNED BY public.baseline_checks.id;


--
-- Name: baselines; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.baselines (
    id integer NOT NULL,
    name character varying(100) NOT NULL,
    description text,
    scope_smart_group_id integer,
    rules_json text NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    schedule_interval_hours integer DEFAULT 24 NOT NULL,
    last_run_at timestamp without time zone,
    created_by integer,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: baselines_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.baselines_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: baselines_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.baselines_id_seq OWNED BY public.baselines.id;


--
-- Name: ca_rotations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ca_rotations (
    id integer NOT NULL,
    event_type character varying(20) NOT NULL,
    ca_identifier character varying(100),
    ca_public_key text,
    performed_by integer,
    performed_at timestamp without time zone DEFAULT now() NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: ca_rotations_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ca_rotations_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ca_rotations_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ca_rotations_id_seq OWNED BY public.ca_rotations.id;


--
-- Name: command_approval_votes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.command_approval_votes (
    id integer NOT NULL,
    approval_id integer NOT NULL,
    user_id integer NOT NULL,
    decision character varying(20) NOT NULL,
    comment text,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: command_approval_votes_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.command_approval_votes_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: command_approval_votes_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.command_approval_votes_id_seq OWNED BY public.command_approval_votes.id;


--
-- Name: command_approvals; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.command_approvals (
    id integer NOT NULL,
    command character varying(1000) NOT NULL,
    system_id integer NOT NULL,
    whitelist_entry_id integer,
    requested_by integer NOT NULL,
    decided_by integer,
    status character varying(20) DEFAULT 'pending'::character varying NOT NULL,
    comment text,
    timeout_seconds integer,
    session_id character varying(255),
    requested_at timestamp without time zone DEFAULT now() NOT NULL,
    decided_at timestamp without time zone,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL,
    expires_at timestamp without time zone,
    required_approvals integer DEFAULT 1 NOT NULL
);


--
-- Name: command_approvals_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.command_approvals_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: command_approvals_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.command_approvals_id_seq OWNED BY public.command_approvals.id;


--
-- Name: command_distro_mapping; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.command_distro_mapping (
    id integer NOT NULL,
    command_id integer NOT NULL,
    distro_id integer NOT NULL,
    distro_version_pattern character varying(100),
    command_override character varying(500),
    is_supported boolean NOT NULL,
    notes text,
    created_at timestamp without time zone,
    updated_at timestamp without time zone
);


--
-- Name: command_distro_mapping_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.command_distro_mapping_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: command_distro_mapping_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.command_distro_mapping_id_seq OWNED BY public.command_distro_mapping.id;


--
-- Name: command_execution_metrics; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.command_execution_metrics (
    id integer NOT NULL,
    system_id integer NOT NULL,
    user_id integer,
    metric_date timestamp without time zone NOT NULL,
    metric_hour integer NOT NULL,
    total_executions integer NOT NULL,
    successful_executions integer NOT NULL,
    failed_executions integer NOT NULL,
    timeout_executions integer NOT NULL,
    avg_execution_time_ms integer,
    max_execution_time_ms integer,
    min_execution_time_ms integer,
    avg_memory_usage_bytes bigint,
    max_memory_usage_bytes bigint,
    total_cpu_time_ms bigint,
    validation_failures integer NOT NULL,
    high_risk_executions integer NOT NULL,
    sudo_executions integer NOT NULL,
    created_at timestamp without time zone,
    updated_at timestamp without time zone
);


--
-- Name: command_execution_metrics_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.command_execution_metrics_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: command_execution_metrics_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.command_execution_metrics_id_seq OWNED BY public.command_execution_metrics.id;


--
-- Name: command_execution_policies; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.command_execution_policies (
    id integer NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    default_timeout_seconds integer NOT NULL,
    max_timeout_seconds integer NOT NULL,
    max_memory_bytes bigint,
    max_cpu_time_ms integer,
    max_disk_io_bytes bigint,
    max_network_io_bytes bigint,
    max_open_files integer,
    max_processes integer,
    allow_sudo boolean NOT NULL,
    allow_network_access boolean NOT NULL,
    allow_file_system_write boolean NOT NULL,
    require_validation boolean NOT NULL,
    max_retry_attempts integer NOT NULL,
    retry_delay_seconds integer NOT NULL,
    log_stdout boolean NOT NULL,
    log_stderr boolean NOT NULL,
    monitor_resources boolean NOT NULL,
    applies_to_all_systems boolean NOT NULL,
    applies_to_all_users boolean NOT NULL,
    is_active boolean NOT NULL,
    priority integer NOT NULL,
    created_at timestamp without time zone,
    updated_at timestamp without time zone,
    created_by integer NOT NULL
);


--
-- Name: command_execution_policies_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.command_execution_policies_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: command_execution_policies_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.command_execution_policies_id_seq OWNED BY public.command_execution_policies.id;


--
-- Name: command_execution_queue; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.command_execution_queue (
    id integer NOT NULL,
    system_id integer NOT NULL,
    user_id integer NOT NULL,
    command text NOT NULL,
    priority integer NOT NULL,
    status character varying(50) NOT NULL,
    scheduled_at timestamp without time zone,
    started_at timestamp without time zone,
    completed_at timestamp without time zone,
    timeout_seconds integer NOT NULL,
    retry_count integer NOT NULL,
    max_retries integer NOT NULL,
    execution_result_id integer,
    error_message text,
    created_at timestamp without time zone,
    updated_at timestamp without time zone
);


--
-- Name: command_execution_queue_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.command_execution_queue_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: command_execution_queue_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.command_execution_queue_id_seq OWNED BY public.command_execution_queue.id;


--
-- Name: command_execution_results; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.command_execution_results (
    id integer NOT NULL,
    system_id integer NOT NULL,
    user_id integer NOT NULL,
    session_id character varying(255),
    command text NOT NULL,
    normalized_command text,
    command_hash character varying(64) NOT NULL,
    execution_status character varying(50) NOT NULL,
    exit_code integer,
    stdout text,
    stderr text,
    started_at timestamp without time zone NOT NULL,
    completed_at timestamp without time zone,
    execution_time_ms integer,
    timeout_seconds integer NOT NULL,
    max_memory_usage_bytes bigint,
    cpu_time_ms integer,
    disk_io_bytes bigint,
    network_io_bytes bigint,
    validation_status character varying(50) NOT NULL,
    risk_level character varying(50) NOT NULL,
    requires_sudo boolean NOT NULL,
    actual_user character varying(100),
    ip_address inet,
    user_agent character varying(500),
    execution_context text,
    error_type character varying(100),
    error_message text,
    retry_count integer NOT NULL,
    created_at timestamp without time zone,
    updated_at timestamp without time zone,
    transport character varying(8)
);


--
-- Name: command_execution_results_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.command_execution_results_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: command_execution_results_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.command_execution_results_id_seq OWNED BY public.command_execution_results.id;


--
-- Name: command_execution_system_policies; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.command_execution_system_policies (
    id integer NOT NULL,
    policy_id integer NOT NULL,
    system_id integer NOT NULL,
    timeout_override integer,
    memory_limit_override bigint,
    is_active boolean NOT NULL,
    created_at timestamp without time zone,
    updated_at timestamp without time zone
);


--
-- Name: command_execution_system_policies_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.command_execution_system_policies_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: command_execution_system_policies_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.command_execution_system_policies_id_seq OWNED BY public.command_execution_system_policies.id;


--
-- Name: command_execution_user_policies; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.command_execution_user_policies (
    id integer NOT NULL,
    policy_id integer NOT NULL,
    user_id integer NOT NULL,
    timeout_override integer,
    memory_limit_override bigint,
    is_active boolean NOT NULL,
    created_at timestamp without time zone,
    updated_at timestamp without time zone
);


--
-- Name: command_execution_user_policies_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.command_execution_user_policies_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: command_execution_user_policies_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.command_execution_user_policies_id_seq OWNED BY public.command_execution_user_policies.id;


--
-- Name: command_resource_limits; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.command_resource_limits (
    id integer NOT NULL,
    execution_result_id integer NOT NULL,
    max_memory_bytes bigint,
    max_cpu_time_ms integer,
    max_disk_io_bytes bigint,
    max_network_io_bytes bigint,
    max_open_files integer,
    max_processes integer,
    memory_limit_exceeded boolean NOT NULL,
    cpu_limit_exceeded boolean NOT NULL,
    disk_io_limit_exceeded boolean NOT NULL,
    network_io_limit_exceeded boolean NOT NULL,
    limit_source character varying(100) NOT NULL,
    policy_name character varying(255),
    created_at timestamp without time zone,
    updated_at timestamp without time zone
);


--
-- Name: command_resource_limits_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.command_resource_limits_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: command_resource_limits_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.command_resource_limits_id_seq OWNED BY public.command_resource_limits.id;


--
-- Name: command_template_distros; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.command_template_distros (
    id integer NOT NULL,
    template_id integer NOT NULL,
    distro_id integer NOT NULL,
    distro_version_pattern character varying(100),
    template_override character varying(1000),
    is_supported boolean NOT NULL,
    created_at timestamp without time zone,
    updated_at timestamp without time zone
);


--
-- Name: command_template_distros_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.command_template_distros_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: command_template_distros_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.command_template_distros_id_seq OWNED BY public.command_template_distros.id;


--
-- Name: command_templates; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.command_templates (
    id integer NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    template character varying(1000) NOT NULL,
    category character varying(100) NOT NULL,
    parameters text,
    is_active boolean NOT NULL,
    risk_level character varying(50) NOT NULL,
    requires_approval boolean NOT NULL,
    created_at timestamp without time zone,
    updated_at timestamp without time zone,
    created_by integer NOT NULL
);


--
-- Name: command_templates_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.command_templates_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: command_templates_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.command_templates_id_seq OWNED BY public.command_templates.id;


--
-- Name: command_validation_logs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.command_validation_logs (
    id integer NOT NULL,
    command_id integer,
    validation_rule_id integer,
    system_id integer NOT NULL,
    raw_command character varying(1000) NOT NULL,
    normalized_command character varying(1000),
    validation_status character varying(50) NOT NULL,
    validation_reason text,
    user_id integer NOT NULL,
    session_id character varying(255),
    ip_address inet,
    user_agent character varying(500),
    created_at timestamp without time zone,
    updated_at timestamp without time zone NOT NULL
);


--
-- Name: command_validation_logs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.command_validation_logs_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: command_validation_logs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.command_validation_logs_id_seq OWNED BY public.command_validation_logs.id;


--
-- Name: command_validation_rules; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.command_validation_rules (
    id integer NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    validation_type character varying(50) NOT NULL,
    pattern character varying(1000) NOT NULL,
    is_regex boolean NOT NULL,
    is_active boolean NOT NULL,
    severity character varying(50) NOT NULL,
    error_message character varying(500),
    created_at timestamp without time zone,
    updated_at timestamp without time zone,
    created_by integer NOT NULL
);


--
-- Name: command_validation_rules_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.command_validation_rules_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: command_validation_rules_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.command_validation_rules_id_seq OWNED BY public.command_validation_rules.id;


--
-- Name: command_whitelist; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.command_whitelist (
    id integer NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    command_pattern character varying(500) NOT NULL,
    is_regex boolean NOT NULL,
    is_active boolean NOT NULL,
    risk_level character varying(50) NOT NULL,
    category character varying(100) NOT NULL,
    requires_sudo boolean NOT NULL,
    timeout_seconds integer NOT NULL,
    created_at timestamp without time zone,
    updated_at timestamp without time zone,
    created_by integer NOT NULL,
    requires_approval boolean DEFAULT false NOT NULL,
    required_approvals integer DEFAULT 1 NOT NULL
);


--
-- Name: command_whitelist_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.command_whitelist_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: command_whitelist_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.command_whitelist_id_seq OWNED BY public.command_whitelist.id;


--
-- Name: compliance_policies; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.compliance_policies (
    id integer NOT NULL,
    slug character varying(64) NOT NULL,
    name character varying(128) NOT NULL,
    description text,
    severity character varying(16) DEFAULT 'medium'::character varying NOT NULL,
    category character varying(64) DEFAULT 'custom'::character varying NOT NULL,
    schedule_interval_hours integer DEFAULT 24 NOT NULL,
    evidence_retention_days integer DEFAULT 90 NOT NULL,
    remediation_guidance text,
    enabled boolean DEFAULT true NOT NULL,
    version integer DEFAULT 1 NOT NULL,
    built_in boolean DEFAULT false NOT NULL,
    starter_pack_key character varying(128),
    created_by integer NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    last_run_at timestamp without time zone,
    last_run_status character varying(16)
);


--
-- Name: compliance_policies_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.compliance_policies_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: compliance_policies_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.compliance_policies_id_seq OWNED BY public.compliance_policies.id;


--
-- Name: compliance_policy_checks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.compliance_policy_checks (
    id integer NOT NULL,
    policy_id integer NOT NULL,
    slug character varying(64) NOT NULL,
    title character varying(256) NOT NULL,
    description text,
    kind character varying(64) NOT NULL,
    definition_json jsonb NOT NULL,
    severity_override character varying(16),
    remediation_guidance text,
    enabled boolean DEFAULT true NOT NULL,
    display_order integer DEFAULT 0 NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


--
-- Name: compliance_policy_checks_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.compliance_policy_checks_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: compliance_policy_checks_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.compliance_policy_checks_id_seq OWNED BY public.compliance_policy_checks.id;


--
-- Name: compliance_policy_evidence; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.compliance_policy_evidence (
    id integer NOT NULL,
    policy_id integer NOT NULL,
    check_id integer,
    system_id integer NOT NULL,
    policy_slug character varying(64) NOT NULL,
    policy_version integer NOT NULL,
    check_slug character varying(64) NOT NULL,
    check_kind character varying(64) NOT NULL,
    verdict character varying(16) NOT NULL,
    verdict_reason character varying(512),
    observed_value text,
    expected_value text,
    severity character varying(16) NOT NULL,
    evaluation_run_id character varying(36) NOT NULL,
    evaluated_at timestamp without time zone NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


--
-- Name: compliance_policy_evidence_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.compliance_policy_evidence_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: compliance_policy_evidence_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.compliance_policy_evidence_id_seq OWNED BY public.compliance_policy_evidence.id;


--
-- Name: compliance_remediation_execution_attempts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.compliance_remediation_execution_attempts (
    id integer NOT NULL,
    request_id integer NOT NULL,
    plan_id integer,
    policy_id integer NOT NULL,
    check_id integer,
    system_id integer NOT NULL,
    policy_slug character varying(64) NOT NULL,
    policy_version integer NOT NULL,
    check_slug character varying(64) NOT NULL,
    check_kind character varying(64) NOT NULL,
    severity_snapshot character varying(16) NOT NULL,
    plan_kind_snapshot character varying(64) NOT NULL,
    package_name character varying(256),
    package_version_target character varying(128),
    approval_decided_by integer,
    approval_decided_at timestamp without time zone,
    state character varying(16) DEFAULT 'pending'::character varying NOT NULL,
    transport character varying(32),
    failure_reason character varying(64),
    error_message character varying(2048),
    dispatched_at timestamp without time zone,
    completed_at timestamp without time zone,
    created_by integer NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    exit_code integer,
    duration_ms integer,
    stdout_summary text,
    stderr_summary text,
    dispatch_details jsonb DEFAULT '{}'::jsonb NOT NULL
);


--
-- Name: compliance_remediation_execution_attempts_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.compliance_remediation_execution_attempts_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: compliance_remediation_execution_attempts_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.compliance_remediation_execution_attempts_id_seq OWNED BY public.compliance_remediation_execution_attempts.id;


--
-- Name: compliance_remediation_plans; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.compliance_remediation_plans (
    id integer NOT NULL,
    request_id integer NOT NULL,
    policy_id integer NOT NULL,
    check_id integer,
    system_id integer NOT NULL,
    policy_slug character varying(64) NOT NULL,
    policy_version integer NOT NULL,
    check_slug character varying(64) NOT NULL,
    check_kind character varying(64) NOT NULL,
    severity_snapshot character varying(16) NOT NULL,
    state character varying(16) DEFAULT 'planned'::character varying NOT NULL,
    plan_kind character varying(64) NOT NULL,
    plan_steps jsonb NOT NULL,
    unsupported_reason character varying(512),
    error_message character varying(512),
    created_by integer NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    check_definition_fingerprint character varying(64),
    acknowledged_at timestamp without time zone,
    acknowledged_by integer,
    superseded_by_plan_id integer
);


--
-- Name: compliance_remediation_plans_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.compliance_remediation_plans_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: compliance_remediation_plans_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.compliance_remediation_plans_id_seq OWNED BY public.compliance_remediation_plans.id;


--
-- Name: compliance_remediation_requests; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.compliance_remediation_requests (
    id integer NOT NULL,
    policy_id integer NOT NULL,
    check_id integer,
    system_id integer NOT NULL,
    evidence_id integer,
    policy_slug character varying(64) NOT NULL,
    policy_version integer NOT NULL,
    check_slug character varying(64) NOT NULL,
    check_kind character varying(64) NOT NULL,
    evaluation_run_id character varying(36),
    verdict_snapshot character varying(16) NOT NULL,
    verdict_reason_snapshot character varying(512),
    severity_snapshot character varying(16) NOT NULL,
    remediation_guidance_snapshot text,
    state character varying(16) DEFAULT 'requested'::character varying NOT NULL,
    justification text,
    requested_by integer NOT NULL,
    decided_by integer,
    decided_at timestamp without time zone,
    decided_reason text,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


--
-- Name: compliance_remediation_requests_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.compliance_remediation_requests_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: compliance_remediation_requests_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.compliance_remediation_requests_id_seq OWNED BY public.compliance_remediation_requests.id;


--
-- Name: content_channel_repos; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.content_channel_repos (
    id integer NOT NULL,
    channel_id integer NOT NULL,
    mirror_id integer NOT NULL,
    suite_override character varying(64),
    pinned_run_id integer,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


--
-- Name: content_channel_repos_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.content_channel_repos_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: content_channel_repos_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.content_channel_repos_id_seq OWNED BY public.content_channel_repos.id;


--
-- Name: content_channels; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.content_channels (
    id integer NOT NULL,
    slug character varying(64) NOT NULL,
    display_name character varying(128) NOT NULL,
    package_family character varying(8) NOT NULL,
    description text,
    deleted_at timestamp without time zone,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT content_channels_package_family_valid CHECK (((package_family)::text = ANY ((ARRAY['deb'::character varying, 'rpm'::character varying])::text[])))
);


--
-- Name: content_channels_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.content_channels_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: content_channels_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.content_channels_id_seq OWNED BY public.content_channels.id;


--
-- Name: content_profile_channels; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.content_profile_channels (
    id integer NOT NULL,
    profile_id integer NOT NULL,
    channel_id integer NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


--
-- Name: content_profile_channels_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.content_profile_channels_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: content_profile_channels_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.content_profile_channels_id_seq OWNED BY public.content_profile_channels.id;


--
-- Name: content_profiles; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.content_profiles (
    id integer NOT NULL,
    slug character varying(64) NOT NULL,
    display_name character varying(128) NOT NULL,
    package_family character varying(8) NOT NULL,
    description text,
    deleted_at timestamp without time zone,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT content_profiles_package_family_valid CHECK (((package_family)::text = ANY ((ARRAY['deb'::character varying, 'rpm'::character varying])::text[])))
);


--
-- Name: content_profiles_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.content_profiles_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: content_profiles_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.content_profiles_id_seq OWNED BY public.content_profiles.id;


--
-- Name: credentials; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.credentials (
    id integer NOT NULL,
    name character varying(255) NOT NULL,
    auth_method character varying(50) NOT NULL,
    username character varying(255),
    created_at timestamp without time zone,
    updated_at timestamp without time zone,
    sudo_method character varying(50) DEFAULT 'none'::character varying NOT NULL,
    vault_path character varying(512)
);


--
-- Name: credentials_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.credentials_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: credentials_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.credentials_id_seq OWNED BY public.credentials.id;


--
-- Name: distro_lifecycle; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.distro_lifecycle (
    id integer NOT NULL,
    distro_id character varying(64) NOT NULL,
    release character varying(64) NOT NULL,
    eol_date date NOT NULL,
    support_kind character varying(16) NOT NULL,
    source character varying(255) NOT NULL,
    as_of date NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT distro_lifecycle_support_kind_valid CHECK (((support_kind)::text = ANY ((ARRAY['standard'::character varying, 'esm'::character varying, 'extended'::character varying])::text[])))
);


--
-- Name: distro_lifecycle_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.distro_lifecycle_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: distro_lifecycle_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.distro_lifecycle_id_seq OWNED BY public.distro_lifecycle.id;


--
-- Name: distro_lifecycle_override; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.distro_lifecycle_override (
    id integer NOT NULL,
    scope_type character varying(16) NOT NULL,
    scope_id integer NOT NULL,
    distro_id character varying(64) NOT NULL,
    release character varying(64) NOT NULL,
    eol_date date NOT NULL,
    support_kind character varying(16) NOT NULL,
    source character varying(255) NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT distro_lifecycle_override_scope_type_valid CHECK (((scope_type)::text = 'smart_group'::text)),
    CONSTRAINT distro_lifecycle_override_support_kind_valid CHECK (((support_kind)::text = 'extended'::text))
);


--
-- Name: distro_lifecycle_override_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.distro_lifecycle_override_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: distro_lifecycle_override_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.distro_lifecycle_override_id_seq OWNED BY public.distro_lifecycle_override.id;


--
-- Name: distros; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.distros (
    id integer NOT NULL,
    name character varying(255) NOT NULL,
    version character varying(50) NOT NULL,
    release_date date NOT NULL,
    end_of_life_date date NOT NULL,
    created_at timestamp without time zone,
    updated_at timestamp without time zone
);


--
-- Name: distros_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.distros_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: distros_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.distros_id_seq OWNED BY public.distros.id;


--
-- Name: file_transfer_audits; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.file_transfer_audits (
    id integer NOT NULL,
    user_id integer,
    system_id integer,
    login character varying(100) NOT NULL,
    direction character varying(20) NOT NULL,
    remote_path text NOT NULL,
    local_filename text,
    size_bytes bigint DEFAULT '0'::bigint NOT NULL,
    sha256 character varying(64),
    status character varying(20) DEFAULT 'in_progress'::character varying NOT NULL,
    error_message text,
    client_ip character varying(64),
    started_at timestamp without time zone DEFAULT now() NOT NULL,
    ended_at timestamp without time zone,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL,
    transport character varying(8)
);


--
-- Name: file_transfer_audits_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.file_transfer_audits_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: file_transfer_audits_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.file_transfer_audits_id_seq OWNED BY public.file_transfer_audits.id;


--
-- Name: fleet_operation_results; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.fleet_operation_results (
    id integer NOT NULL,
    fleet_operation_id integer NOT NULL,
    system_id integer,
    status character varying(50) NOT NULL,
    error_message text,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: fleet_operation_results_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.fleet_operation_results_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: fleet_operation_results_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.fleet_operation_results_id_seq OWNED BY public.fleet_operation_results.id;


--
-- Name: fleet_operations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.fleet_operations (
    id integer NOT NULL,
    operation_type character varying(100) NOT NULL,
    user_id integer NOT NULL,
    target_count integer DEFAULT 0 NOT NULL,
    success_count integer DEFAULT 0 NOT NULL,
    failure_count integer DEFAULT 0 NOT NULL,
    parameters text,
    status character varying(50) DEFAULT 'running'::character varying NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    completed_at timestamp without time zone,
    updated_at timestamp without time zone DEFAULT now()
);


--
-- Name: fleet_operations_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.fleet_operations_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: fleet_operations_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.fleet_operations_id_seq OWNED BY public.fleet_operations.id;


--
-- Name: fleet_roles; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.fleet_roles (
    id integer NOT NULL,
    name character varying(100) NOT NULL,
    description text,
    login_mode character varying(20) DEFAULT 'per_user'::character varying NOT NULL,
    role_account_name character varying(100),
    allowed_actions_json text NOT NULL,
    session_requires_approval boolean DEFAULT false NOT NULL,
    totp_required boolean DEFAULT false NOT NULL,
    idle_timeout_s integer DEFAULT 900 NOT NULL,
    max_session_s integer DEFAULT 3600 NOT NULL,
    os_groups_json text DEFAULT '[]'::text NOT NULL,
    sudoers_snippet text,
    is_builtin boolean DEFAULT false NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL,
    recording_retention_days integer DEFAULT 90 NOT NULL
);


--
-- Name: fleet_roles_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.fleet_roles_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: fleet_roles_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.fleet_roles_id_seq OWNED BY public.fleet_roles.id;


--
-- Name: global_connection_settings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.global_connection_settings (
    id integer NOT NULL,
    connection_timeout integer DEFAULT 10 NOT NULL,
    max_pool_size integer DEFAULT 50 NOT NULL,
    pool_cleanup_interval integer DEFAULT 300 NOT NULL,
    max_idle_time integer DEFAULT 600 NOT NULL,
    unreachable_threshold integer DEFAULT 2 NOT NULL,
    default_ssh_port integer DEFAULT 22 NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL,
    transport_failure_threshold integer DEFAULT 3 NOT NULL,
    transport_cooldown_seconds integer DEFAULT 60 NOT NULL
);


--
-- Name: global_connection_settings_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.global_connection_settings_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: global_connection_settings_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.global_connection_settings_id_seq OWNED BY public.global_connection_settings.id;


--
-- Name: group_content_profile_subscriptions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.group_content_profile_subscriptions (
    id integer NOT NULL,
    group_id integer NOT NULL,
    profile_id integer NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


--
-- Name: group_content_profile_subscriptions_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.group_content_profile_subscriptions_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: group_content_profile_subscriptions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.group_content_profile_subscriptions_id_seq OWNED BY public.group_content_profile_subscriptions.id;


--
-- Name: groups; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.groups (
    id integer NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    parent_id integer,
    created_at timestamp without time zone,
    updated_at timestamp without time zone
);


--
-- Name: groups_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.groups_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: groups_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.groups_id_seq OWNED BY public.groups.id;


--
-- Name: host_content_profile_subscriptions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.host_content_profile_subscriptions (
    id integer NOT NULL,
    host_id integer NOT NULL,
    profile_id integer NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


--
-- Name: host_content_profile_subscriptions_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.host_content_profile_subscriptions_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: host_content_profile_subscriptions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.host_content_profile_subscriptions_id_seq OWNED BY public.host_content_profile_subscriptions.id;


--
-- Name: host_facts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.host_facts (
    id integer NOT NULL,
    system_id integer NOT NULL,
    schema_version integer NOT NULL,
    collected_at timestamp without time zone NOT NULL,
    source_transport character varying(16) NOT NULL,
    cpu_model character varying(255),
    cpu_cores integer,
    ram_total_bytes bigint,
    kernel_version character varying(255),
    distro_id_facts character varying(64),
    distro_release character varying(64),
    uptime_seconds bigint,
    reboot_required boolean,
    package_manager character varying(32),
    package_manager_version character varying(64),
    virtualization character varying(32),
    cloud_provider character varying(32),
    cloud_instance_metadata jsonb,
    disks jsonb,
    partial_errors jsonb,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    ssh_permit_root_login character varying(64),
    ssh_password_authentication character varying(64),
    sysctl_kernel_randomize_va_space character varying(64),
    sysctl_net_ipv4_ip_forward character varying(64),
    sysctl_net_ipv4_conf_all_rp_filter character varying(64),
    CONSTRAINT host_facts_cpu_cores_nonneg CHECK (((cpu_cores IS NULL) OR (cpu_cores >= 0))),
    CONSTRAINT host_facts_ram_nonneg CHECK (((ram_total_bytes IS NULL) OR (ram_total_bytes >= 0))),
    CONSTRAINT host_facts_schema_version_positive CHECK ((schema_version >= 1)),
    CONSTRAINT host_facts_source_transport_valid CHECK (((source_transport)::text = ANY ((ARRAY['agent'::character varying, 'ssh'::character varying, 'manual'::character varying])::text[]))),
    CONSTRAINT host_facts_uptime_nonneg CHECK (((uptime_seconds IS NULL) OR (uptime_seconds >= 0)))
);


--
-- Name: host_facts_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.host_facts_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: host_facts_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.host_facts_id_seq OWNED BY public.host_facts.id;


--
-- Name: host_mirror_serve_credentials; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.host_mirror_serve_credentials (
    id integer NOT NULL,
    host_id integer NOT NULL,
    mirror_id integer NOT NULL,
    token_hash character varying(255) NOT NULL,
    issued_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    expires_at timestamp without time zone NOT NULL,
    last_used_at timestamp without time zone,
    revoked_at timestamp without time zone,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    token_id character varying(64)
);


--
-- Name: host_mirror_serve_credentials_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.host_mirror_serve_credentials_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: host_mirror_serve_credentials_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.host_mirror_serve_credentials_id_seq OWNED BY public.host_mirror_serve_credentials.id;


--
-- Name: host_mirror_trust; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.host_mirror_trust (
    id integer NOT NULL,
    host_id integer NOT NULL,
    mirror_id integer NOT NULL,
    installed_fingerprints jsonb DEFAULT '[]'::jsonb NOT NULL,
    last_installed_at timestamp without time zone,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


--
-- Name: host_mirror_trust_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.host_mirror_trust_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: host_mirror_trust_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.host_mirror_trust_id_seq OWNED BY public.host_mirror_trust.id;


--
-- Name: host_user_states; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.host_user_states (
    id integer NOT NULL,
    system_id integer NOT NULL,
    login character varying(100) NOT NULL,
    mode character varying(20) NOT NULL,
    state character varying(20) DEFAULT 'pending'::character varying NOT NULL,
    last_error text,
    last_reconciled_at timestamp without time zone,
    home_archive_path text,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL,
    privilege_reconcile_pending boolean DEFAULT false NOT NULL
);


--
-- Name: host_user_states_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.host_user_states_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: host_user_states_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.host_user_states_id_seq OWNED BY public.host_user_states.id;


--
-- Name: job_history; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.job_history (
    id integer NOT NULL,
    job_id integer NOT NULL,
    start_time timestamp without time zone NOT NULL,
    end_time timestamp without time zone,
    status character varying(50) NOT NULL,
    result text,
    error_message text,
    created_at timestamp without time zone,
    updated_at timestamp without time zone,
    systems_targeted integer DEFAULT 0,
    systems_completed integer DEFAULT 0,
    systems_failed integer DEFAULT 0
);


--
-- Name: job_history_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.job_history_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: job_history_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.job_history_id_seq OWNED BY public.job_history.id;


--
-- Name: jobs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.jobs (
    id integer NOT NULL,
    job_type character varying(50) NOT NULL,
    schedule character varying(100),
    status character varying(50) NOT NULL,
    last_run timestamp without time zone,
    next_run timestamp without time zone,
    created_at timestamp without time zone,
    created_by integer NOT NULL,
    updated_at timestamp without time zone,
    name character varying(200) DEFAULT 'Unnamed Job'::character varying NOT NULL,
    description text,
    is_recurring boolean DEFAULT false NOT NULL,
    target_type character varying(50) DEFAULT 'system'::character varying NOT NULL,
    target_ids text,
    package_filter text,
    tag_match_logic character varying(10) DEFAULT 'or'::character varying,
    max_parallel integer DEFAULT 1 NOT NULL,
    depends_on_job_id integer,
    chain_condition character varying(50) DEFAULT 'on_success'::character varying NOT NULL
);


--
-- Name: jobs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.jobs_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: jobs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.jobs_id_seq OWNED BY public.jobs.id;


--
-- Name: lifecycle_notification_state; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.lifecycle_notification_state (
    id integer NOT NULL,
    system_id integer NOT NULL,
    event_type character varying(64) NOT NULL,
    threshold_days integer NOT NULL,
    effective_eol_date date NOT NULL,
    notified_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT lifecycle_notification_state_event_type_valid CHECK (((event_type)::text = ANY ((ARRAY['host_eol_approaching'::character varying, 'host_eol_reached'::character varying])::text[])))
);


--
-- Name: lifecycle_notification_state_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.lifecycle_notification_state_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: lifecycle_notification_state_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.lifecycle_notification_state_id_seq OWNED BY public.lifecycle_notification_state.id;


--
-- Name: maintenance_windows; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.maintenance_windows (
    id integer NOT NULL,
    name character varying(100) NOT NULL,
    target_type character varying(50) NOT NULL,
    target_id integer,
    schedule text NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    created_by integer NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: maintenance_windows_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.maintenance_windows_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: maintenance_windows_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.maintenance_windows_id_seq OWNED BY public.maintenance_windows.id;


--
-- Name: mirror_alert_state; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mirror_alert_state (
    id integer NOT NULL,
    mirror_repo_id integer NOT NULL,
    event_type character varying(64) NOT NULL,
    last_fired_at timestamp without time zone NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT mirror_alert_state_event_type_valid CHECK (((event_type)::text = ANY ((ARRAY['mirror_sync_failed'::character varying, 'mirror_sync_completed'::character varying, 'mirror_disk_pressure'::character varying, 'mirror_upstream_signature_invalid'::character varying])::text[])))
);


--
-- Name: mirror_alert_state_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mirror_alert_state_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mirror_alert_state_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mirror_alert_state_id_seq OWNED BY public.mirror_alert_state.id;


--
-- Name: mirror_repos; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mirror_repos (
    id integer NOT NULL,
    slug character varying(64) NOT NULL,
    display_name character varying(128) NOT NULL,
    package_family character varying(8) NOT NULL,
    upstream_url character varying(512) NOT NULL,
    distribution character varying(64) NOT NULL,
    components text DEFAULT '[]'::text NOT NULL,
    architectures text DEFAULT '[]'::text NOT NULL,
    sync_schedule_cron character varying(128) NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    source_mode character varying(20) DEFAULT 'upstream_sync'::character varying NOT NULL,
    verify_upstream_signature boolean DEFAULT true NOT NULL,
    retention_keep_count integer DEFAULT 10 NOT NULL,
    retention_keep_within_days integer DEFAULT 30 NOT NULL,
    disk_budget_bytes bigint,
    last_sync_started_at timestamp without time zone,
    last_sync_finished_at timestamp without time zone,
    last_sync_status character varying(16) DEFAULT 'idle'::character varying NOT NULL,
    last_sync_error text,
    current_disk_bytes bigint DEFAULT 0 NOT NULL,
    deleted_at timestamp without time zone,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT mirror_repos_current_disk_bytes_nonneg CHECK ((current_disk_bytes >= 0)),
    CONSTRAINT mirror_repos_disk_budget_positive CHECK (((disk_budget_bytes IS NULL) OR (disk_budget_bytes > 0))),
    CONSTRAINT mirror_repos_last_sync_status_valid CHECK (((last_sync_status)::text = ANY ((ARRAY['idle'::character varying, 'running'::character varying, 'ok'::character varying, 'failed'::character varying])::text[]))),
    CONSTRAINT mirror_repos_package_family_valid CHECK (((package_family)::text = ANY ((ARRAY['deb'::character varying, 'rpm'::character varying])::text[]))),
    CONSTRAINT mirror_repos_retention_keep_count_positive CHECK ((retention_keep_count >= 1)),
    CONSTRAINT mirror_repos_retention_keep_within_days_nonneg CHECK ((retention_keep_within_days >= 0)),
    CONSTRAINT mirror_repos_source_mode_valid CHECK (((source_mode)::text = ANY ((ARRAY['upstream_sync'::character varying, 'imported_offline'::character varying])::text[])))
);


--
-- Name: mirror_repos_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mirror_repos_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mirror_repos_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mirror_repos_id_seq OWNED BY public.mirror_repos.id;


--
-- Name: mirror_signing_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mirror_signing_keys (
    id integer NOT NULL,
    mirror_repo_id integer NOT NULL,
    status character varying(20) NOT NULL,
    gpg_fingerprint character varying(64) NOT NULL,
    key_uid character varying(255) NOT NULL,
    vault_path character varying(255) NOT NULL,
    cutover_at timestamp without time zone,
    retired_at timestamp without time zone,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    armored_public_key text,
    CONSTRAINT mirror_signing_keys_status_valid CHECK (((status)::text = ANY ((ARRAY['active'::character varying, 'pending_cutover'::character varying, 'rotating_out'::character varying, 'retired'::character varying])::text[])))
);


--
-- Name: mirror_signing_keys_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mirror_signing_keys_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mirror_signing_keys_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mirror_signing_keys_id_seq OWNED BY public.mirror_signing_keys.id;


--
-- Name: mirror_sync_run_packages; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mirror_sync_run_packages (
    id integer NOT NULL,
    mirror_sync_run_id integer NOT NULL,
    mirror_repo_id integer NOT NULL,
    package_name character varying(255) NOT NULL,
    version character varying(255) NOT NULL,
    arch character varying(64),
    filename character varying(512) NOT NULL,
    sha256 character varying(64) NOT NULL,
    size bigint NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


--
-- Name: mirror_sync_run_packages_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mirror_sync_run_packages_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mirror_sync_run_packages_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mirror_sync_run_packages_id_seq OWNED BY public.mirror_sync_run_packages.id;


--
-- Name: mirror_sync_runs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mirror_sync_runs (
    id integer NOT NULL,
    mirror_repo_id integer NOT NULL,
    started_at timestamp without time zone NOT NULL,
    finished_at timestamp without time zone,
    status character varying(16) NOT NULL,
    byte_count bigint,
    package_count integer,
    manifest_sha256 character varying(64),
    manifest_path character varying(512),
    error_text text,
    estimate_unavailable boolean DEFAULT false NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    run_kind character varying(16) DEFAULT 'sync'::character varying NOT NULL,
    manifest_signature_path character varying(512),
    signed_with_key_id integer,
    CONSTRAINT mirror_sync_runs_run_kind_valid CHECK (((run_kind)::text = ANY ((ARRAY['sync'::character varying, 'sign_only'::character varying, 'import'::character varying])::text[]))),
    CONSTRAINT mirror_sync_runs_status_valid CHECK (((status)::text = ANY ((ARRAY['running'::character varying, 'ok'::character varying, 'failed'::character varying])::text[])))
);


--
-- Name: mirror_sync_runs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mirror_sync_runs_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mirror_sync_runs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mirror_sync_runs_id_seq OWNED BY public.mirror_sync_runs.id;


--
-- Name: mirror_upstream_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mirror_upstream_keys (
    id integer NOT NULL,
    name character varying(255) NOT NULL,
    gpg_fingerprint character varying(64) NOT NULL,
    armored_public_key text NOT NULL,
    notes text,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


--
-- Name: mirror_upstream_keys_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.mirror_upstream_keys_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: mirror_upstream_keys_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.mirror_upstream_keys_id_seq OWNED BY public.mirror_upstream_keys.id;


--
-- Name: notification_preferences; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.notification_preferences (
    id integer NOT NULL,
    user_id integer NOT NULL,
    disabled_types text DEFAULT '[]'::text NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: notification_preferences_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.notification_preferences_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: notification_preferences_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.notification_preferences_id_seq OWNED BY public.notification_preferences.id;


--
-- Name: notifications; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.notifications (
    id integer NOT NULL,
    type character varying(50) NOT NULL,
    title character varying(200) NOT NULL,
    message text,
    severity character varying(20) DEFAULT 'info'::character varying NOT NULL,
    is_read boolean DEFAULT false NOT NULL,
    user_id integer,
    related_job_id integer,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: notifications_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.notifications_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: notifications_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.notifications_id_seq OWNED BY public.notifications.id;


--
-- Name: oidc_login_state; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.oidc_login_state (
    id integer NOT NULL,
    state character varying(128) NOT NULL,
    nonce character varying(128) NOT NULL,
    provider_id integer NOT NULL,
    redirect_uri character varying(1024) NOT NULL,
    expires_at timestamp without time zone NOT NULL,
    created_at timestamp without time zone,
    updated_at timestamp without time zone
);


--
-- Name: oidc_login_state_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.oidc_login_state_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: oidc_login_state_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.oidc_login_state_id_seq OWNED BY public.oidc_login_state.id;


--
-- Name: oidc_provider; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.oidc_provider (
    id integer NOT NULL,
    name character varying(255) NOT NULL,
    discovery_url character varying(1024) NOT NULL,
    client_id character varying(255) NOT NULL,
    client_secret character varying(512) NOT NULL,
    role_claim character varying(255) DEFAULT 'roles'::character varying NOT NULL,
    role_mapping text,
    enabled boolean DEFAULT false NOT NULL,
    created_at timestamp without time zone,
    updated_at timestamp without time zone
);


--
-- Name: oidc_provider_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.oidc_provider_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: oidc_provider_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.oidc_provider_id_seq OWNED BY public.oidc_provider.id;


--
-- Name: package_history; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.package_history (
    id integer NOT NULL,
    package_id integer NOT NULL,
    system_id integer NOT NULL,
    operation character varying(50) NOT NULL,
    old_version character varying(50),
    new_version character varying(50),
    performed_at timestamp without time zone NOT NULL,
    performed_by integer,
    job_history_id integer,
    created_at timestamp without time zone,
    updated_at timestamp without time zone,
    status character varying(50) DEFAULT 'completed'::character varying NOT NULL,
    error_message text
);


--
-- Name: package_history_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.package_history_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: package_history_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.package_history_id_seq OWNED BY public.package_history.id;


--
-- Name: package_updates; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.package_updates (
    id integer NOT NULL,
    package_id integer NOT NULL,
    system_id integer NOT NULL,
    available_version character varying(50) NOT NULL,
    update_type character varying(50) NOT NULL,
    discovered_on timestamp without time zone NOT NULL,
    created_at timestamp without time zone,
    updated_at timestamp without time zone
);


--
-- Name: package_updates_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.package_updates_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: package_updates_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.package_updates_id_seq OWNED BY public.package_updates.id;


--
-- Name: packages; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.packages (
    id integer NOT NULL,
    system_id integer NOT NULL,
    name character varying(255) NOT NULL,
    installed_version character varying(50) NOT NULL,
    installation_date timestamp without time zone,
    package_type character varying(50),
    is_security_critical boolean,
    last_audited timestamp without time zone,
    created_at timestamp without time zone,
    updated_at timestamp without time zone,
    is_held boolean DEFAULT false NOT NULL
);


--
-- Name: packages_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.packages_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: packages_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.packages_id_seq OWNED BY public.packages.id;


--
-- Name: patch_advisories; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.patch_advisories (
    id integer NOT NULL,
    source_kind character varying(32) NOT NULL,
    source_advisory_id character varying(128) NOT NULL,
    advisory_class character varying(32) NOT NULL,
    severity character varying(32) NOT NULL,
    title character varying(512) NOT NULL,
    summary text,
    distro_family character varying(32) NOT NULL,
    published_at timestamp without time zone,
    source_updated_at timestamp without time zone,
    cve_ids jsonb,
    external_refs jsonb,
    raw jsonb,
    digest character varying(64) NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT patch_advisories_advisory_class_vocab CHECK (((advisory_class)::text = ANY ((ARRAY['security'::character varying, 'bugfix'::character varying, 'enhancement'::character varying, 'other'::character varying])::text[]))),
    CONSTRAINT patch_advisories_distro_family_vocab CHECK (((distro_family)::text = ANY ((ARRAY['debian'::character varying, 'rhel'::character varying])::text[]))),
    CONSTRAINT patch_advisories_severity_vocab CHECK (((severity)::text = ANY ((ARRAY['critical'::character varying, 'high'::character varying, 'medium'::character varying, 'low'::character varying, 'negligible'::character varying, 'unknown'::character varying])::text[]))),
    CONSTRAINT patch_advisories_source_kind_vocab CHECK (((source_kind)::text = ANY ((ARRAY['ubuntu_usn'::character varying, 'debian_security'::character varying, 'redhat_updateinfo'::character varying])::text[])))
);


--
-- Name: patch_advisories_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.patch_advisories_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: patch_advisories_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.patch_advisories_id_seq OWNED BY public.patch_advisories.id;


--
-- Name: patch_advisory_fixed_packages; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.patch_advisory_fixed_packages (
    id integer NOT NULL,
    advisory_id integer NOT NULL,
    distro_id character varying(32) NOT NULL,
    distro_release character varying(64) NOT NULL,
    package_name character varying(255) NOT NULL,
    fixed_version character varying(255),
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


--
-- Name: patch_advisory_fixed_packages_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.patch_advisory_fixed_packages_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: patch_advisory_fixed_packages_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.patch_advisory_fixed_packages_id_seq OWNED BY public.patch_advisory_fixed_packages.id;


--
-- Name: patch_advisory_host_applicability; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.patch_advisory_host_applicability (
    id integer NOT NULL,
    system_id integer NOT NULL,
    advisory_id integer NOT NULL,
    fixed_package_id integer,
    package_name character varying(255) NOT NULL,
    installed_version character varying(255),
    required_version character varying(255),
    state character varying(32) NOT NULL,
    reason character varying(255),
    evaluated_at timestamp without time zone NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT patch_advisory_host_applicability_state_vocab CHECK (((state)::text = ANY ((ARRAY['applicable'::character varying, 'fixed'::character varying, 'not_applicable'::character varying, 'unknown'::character varying])::text[])))
);


--
-- Name: patch_advisory_host_applicability_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.patch_advisory_host_applicability_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: patch_advisory_host_applicability_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.patch_advisory_host_applicability_id_seq OWNED BY public.patch_advisory_host_applicability.id;


--
-- Name: patch_advisory_imports; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.patch_advisory_imports (
    id integer NOT NULL,
    source_kind character varying(32) NOT NULL,
    status character varying(16) NOT NULL,
    started_at timestamp without time zone NOT NULL,
    finished_at timestamp without time zone,
    imported_count integer DEFAULT 0 NOT NULL,
    refreshed_count integer DEFAULT 0 NOT NULL,
    unchanged_count integer DEFAULT 0 NOT NULL,
    error_count integer DEFAULT 0 NOT NULL,
    error_details jsonb,
    created_by integer NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT patch_advisory_imports_source_kind_vocab CHECK (((source_kind)::text = ANY ((ARRAY['ubuntu_usn'::character varying, 'debian_security'::character varying, 'redhat_updateinfo'::character varying])::text[]))),
    CONSTRAINT patch_advisory_imports_status_vocab CHECK (((status)::text = ANY ((ARRAY['success'::character varying, 'partial'::character varying, 'failed'::character varying])::text[])))
);


--
-- Name: patch_advisory_imports_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.patch_advisory_imports_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: patch_advisory_imports_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.patch_advisory_imports_id_seq OWNED BY public.patch_advisory_imports.id;


--
-- Name: patch_approval_votes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.patch_approval_votes (
    id integer NOT NULL,
    approval_id integer NOT NULL,
    user_id integer NOT NULL,
    decision character varying(20) NOT NULL,
    comment text,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT patch_approval_votes_decision_valid CHECK (((decision)::text = ANY ((ARRAY['approve'::character varying, 'reject'::character varying])::text[])))
);


--
-- Name: patch_approval_votes_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.patch_approval_votes_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: patch_approval_votes_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.patch_approval_votes_id_seq OWNED BY public.patch_approval_votes.id;


--
-- Name: patch_approvals; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.patch_approvals (
    id integer NOT NULL,
    subject_kind character varying(32) NOT NULL,
    subject_id integer NOT NULL,
    status character varying(20) DEFAULT 'pending'::character varying NOT NULL,
    required_approvals integer DEFAULT 1 NOT NULL,
    expires_at timestamp without time zone,
    requested_by integer NOT NULL,
    decided_by integer,
    decided_at timestamp without time zone,
    comment text,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT patch_approvals_required_approvals_positive CHECK ((required_approvals >= 1)),
    CONSTRAINT patch_approvals_status_valid CHECK (((status)::text = ANY ((ARRAY['pending'::character varying, 'approved'::character varying, 'rejected'::character varying, 'expired'::character varying])::text[]))),
    CONSTRAINT patch_approvals_subject_kind_valid CHECK (((subject_kind)::text = ANY ((ARRAY['policy'::character varying, 'plan'::character varying, 'rollback'::character varying])::text[])))
);


--
-- Name: patch_approvals_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.patch_approvals_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: patch_approvals_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.patch_approvals_id_seq OWNED BY public.patch_approvals.id;


--
-- Name: patch_policies; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.patch_policies (
    id integer NOT NULL,
    slug character varying(64) NOT NULL,
    name character varying(128) NOT NULL,
    description text,
    scope_kind character varying(32) NOT NULL,
    scope_packages jsonb DEFAULT '[]'::jsonb NOT NULL,
    reboot_policy character varying(32) NOT NULL,
    reboot_window_id integer,
    maintenance_window_id integer,
    requires_approval boolean DEFAULT false NOT NULL,
    required_approvals integer DEFAULT 1 NOT NULL,
    rollout_cadence character varying(32) NOT NULL,
    failure_policy character varying(32) NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    created_by integer NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    is_fleet_default boolean DEFAULT false NOT NULL,
    CONSTRAINT patch_policies_failure_policy_valid CHECK (((failure_policy)::text = ANY ((ARRAY['continue'::character varying, 'pause_fleet'::character varying])::text[]))),
    CONSTRAINT patch_policies_reboot_policy_valid CHECK (((reboot_policy)::text = ANY ((ARRAY['never'::character varying, 'if_required'::character varying, 'always'::character varying])::text[]))),
    CONSTRAINT patch_policies_required_approvals_positive CHECK ((required_approvals >= 1)),
    CONSTRAINT patch_policies_rollout_cadence_valid CHECK (((rollout_cadence)::text = ANY ((ARRAY['immediate'::character varying, 'staged'::character varying])::text[]))),
    CONSTRAINT patch_policies_scope_kind_valid CHECK (((scope_kind)::text = ANY ((ARRAY['security_only'::character varying, 'full'::character varying, 'package_allowlist'::character varying, 'package_denylist'::character varying])::text[])))
);


--
-- Name: patch_policies_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.patch_policies_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: patch_policies_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.patch_policies_id_seq OWNED BY public.patch_policies.id;


--
-- Name: patch_policy_group_bindings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.patch_policy_group_bindings (
    id integer NOT NULL,
    policy_id integer NOT NULL,
    created_by integer NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    group_id integer NOT NULL
);


--
-- Name: patch_policy_group_bindings_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.patch_policy_group_bindings_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: patch_policy_group_bindings_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.patch_policy_group_bindings_id_seq OWNED BY public.patch_policy_group_bindings.id;


--
-- Name: patch_policy_host_bindings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.patch_policy_host_bindings (
    id integer NOT NULL,
    policy_id integer NOT NULL,
    created_by integer NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    system_id integer NOT NULL
);


--
-- Name: patch_policy_host_bindings_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.patch_policy_host_bindings_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: patch_policy_host_bindings_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.patch_policy_host_bindings_id_seq OWNED BY public.patch_policy_host_bindings.id;


--
-- Name: patch_policy_ring_bindings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.patch_policy_ring_bindings (
    id integer NOT NULL,
    policy_id integer NOT NULL,
    ring_id integer NOT NULL,
    created_by integer NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


--
-- Name: patch_policy_ring_bindings_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.patch_policy_ring_bindings_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: patch_policy_ring_bindings_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.patch_policy_ring_bindings_id_seq OWNED BY public.patch_policy_ring_bindings.id;


--
-- Name: patch_policy_smart_group_bindings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.patch_policy_smart_group_bindings (
    id integer NOT NULL,
    policy_id integer NOT NULL,
    created_by integer NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    smart_group_id integer NOT NULL
);


--
-- Name: patch_policy_smart_group_bindings_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.patch_policy_smart_group_bindings_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: patch_policy_smart_group_bindings_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.patch_policy_smart_group_bindings_id_seq OWNED BY public.patch_policy_smart_group_bindings.id;


--
-- Name: patch_ring_gate_definitions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.patch_ring_gate_definitions (
    id integer NOT NULL,
    ring_id integer NOT NULL,
    signal_key character varying(128) NOT NULL,
    name character varying(128) NOT NULL,
    description text,
    gate_kind character varying(32) NOT NULL,
    comparator character varying(8),
    parameters jsonb,
    required boolean DEFAULT true NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    created_by integer NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT patch_ring_gate_definitions_comparator_vocab CHECK (((comparator IS NULL) OR ((comparator)::text = ANY ((ARRAY['eq'::character varying, 'ne'::character varying, 'gt'::character varying, 'gte'::character varying, 'lt'::character varying, 'lte'::character varying])::text[])))),
    CONSTRAINT patch_ring_gate_definitions_gate_kind_vocab CHECK (((gate_kind)::text = ANY ((ARRAY['boolean'::character varying, 'threshold'::character varying])::text[])))
);


--
-- Name: patch_ring_gate_definitions_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.patch_ring_gate_definitions_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: patch_ring_gate_definitions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.patch_ring_gate_definitions_id_seq OWNED BY public.patch_ring_gate_definitions.id;


--
-- Name: patch_ring_gate_signals; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.patch_ring_gate_signals (
    id integer NOT NULL,
    ring_id integer NOT NULL,
    gate_definition_id integer,
    signal_key character varying(128) NOT NULL,
    status character varying(16) NOT NULL,
    value jsonb,
    details jsonb,
    source_kind character varying(32) NOT NULL,
    source_ref_kind character varying(64),
    source_ref_id character varying(128),
    observed_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    expires_at timestamp without time zone,
    created_by integer NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT patch_ring_gate_signals_source_kind_vocab CHECK (((source_kind)::text = ANY ((ARRAY['manual'::character varying, 'execution'::character varying, 'reboot'::character varying, 'probe'::character varying, 'external'::character varying])::text[]))),
    CONSTRAINT patch_ring_gate_signals_status_vocab CHECK (((status)::text = ANY ((ARRAY['pass'::character varying, 'fail'::character varying])::text[])))
);


--
-- Name: patch_ring_gate_signals_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.patch_ring_gate_signals_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: patch_ring_gate_signals_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.patch_ring_gate_signals_id_seq OWNED BY public.patch_ring_gate_signals.id;


--
-- Name: patch_ring_group_bindings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.patch_ring_group_bindings (
    id integer NOT NULL,
    ring_id integer NOT NULL,
    created_by integer NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    group_id integer NOT NULL
);


--
-- Name: patch_ring_group_bindings_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.patch_ring_group_bindings_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: patch_ring_group_bindings_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.patch_ring_group_bindings_id_seq OWNED BY public.patch_ring_group_bindings.id;


--
-- Name: patch_ring_host_bindings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.patch_ring_host_bindings (
    id integer NOT NULL,
    ring_id integer NOT NULL,
    created_by integer NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    system_id integer NOT NULL
);


--
-- Name: patch_ring_host_bindings_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.patch_ring_host_bindings_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: patch_ring_host_bindings_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.patch_ring_host_bindings_id_seq OWNED BY public.patch_ring_host_bindings.id;


--
-- Name: patch_ring_smart_group_bindings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.patch_ring_smart_group_bindings (
    id integer NOT NULL,
    ring_id integer NOT NULL,
    created_by integer NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    smart_group_id integer NOT NULL
);


--
-- Name: patch_ring_smart_group_bindings_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.patch_ring_smart_group_bindings_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: patch_ring_smart_group_bindings_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.patch_ring_smart_group_bindings_id_seq OWNED BY public.patch_ring_smart_group_bindings.id;


--
-- Name: patch_rings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.patch_rings (
    id integer NOT NULL,
    slug character varying(64) NOT NULL,
    name character varying(128) NOT NULL,
    description text,
    sort_order integer NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    created_by integer NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT patch_rings_sort_order_positive CHECK ((sort_order >= 1))
);


--
-- Name: patch_rings_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.patch_rings_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: patch_rings_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.patch_rings_id_seq OWNED BY public.patch_rings.id;


--
-- Name: patch_rollback_dispatch_host_packages; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.patch_rollback_dispatch_host_packages (
    id integer NOT NULL,
    rollback_dispatch_host_id integer NOT NULL,
    rollback_package_id integer,
    package_name character varying(255) NOT NULL,
    package_manager_family_snapshot character varying(16) NOT NULL,
    target_rollback_version_snapshot character varying(255),
    installed_version_before character varying(255),
    installed_version_after character varying(255),
    outcome character varying(32) NOT NULL,
    error_code character varying(64),
    details jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    verified_at timestamp without time zone,
    CONSTRAINT patch_rollback_dispatch_host_packages_family_vocab CHECK (((package_manager_family_snapshot)::text = ANY ((ARRAY['apt'::character varying, 'dnf'::character varying, 'unknown'::character varying])::text[]))),
    CONSTRAINT patch_rollback_dispatch_host_packages_outcome_vocab CHECK (((outcome)::text = ANY ((ARRAY['pending'::character varying, 'succeeded'::character varying, 'failed'::character varying, 'skipped'::character varying, 'unknown'::character varying])::text[])))
);


--
-- Name: patch_rollback_dispatch_host_packages_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.patch_rollback_dispatch_host_packages_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: patch_rollback_dispatch_host_packages_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.patch_rollback_dispatch_host_packages_id_seq OWNED BY public.patch_rollback_dispatch_host_packages.id;


--
-- Name: patch_rollback_dispatch_hosts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.patch_rollback_dispatch_hosts (
    id integer NOT NULL,
    rollback_dispatch_run_id integer NOT NULL,
    rollback_host_id integer NOT NULL,
    system_id_snapshot integer,
    system_hostname_snapshot character varying(255),
    state character varying(32) NOT NULL,
    error_details jsonb DEFAULT '{}'::jsonb NOT NULL,
    started_at timestamp without time zone,
    completed_at timestamp without time zone,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT patch_rollback_dispatch_hosts_state_vocab CHECK (((state)::text = ANY ((ARRAY['pending'::character varying, 'running'::character varying, 'succeeded'::character varying, 'failed'::character varying, 'skipped'::character varying, 'canceled'::character varying])::text[])))
);


--
-- Name: patch_rollback_dispatch_hosts_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.patch_rollback_dispatch_hosts_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: patch_rollback_dispatch_hosts_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.patch_rollback_dispatch_hosts_id_seq OWNED BY public.patch_rollback_dispatch_hosts.id;


--
-- Name: patch_rollback_dispatch_runs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.patch_rollback_dispatch_runs (
    id integer NOT NULL,
    rollback_id integer NOT NULL,
    rollback_approval_link_id integer NOT NULL,
    state character varying(32) NOT NULL,
    started_by integer NOT NULL,
    started_at timestamp without time zone NOT NULL,
    completed_at timestamp without time zone,
    paused_at timestamp without time zone,
    canceled_at timestamp without time zone,
    max_parallel integer NOT NULL,
    pause_reason text,
    cancel_reason text,
    progress_summary jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT patch_rollback_dispatch_runs_max_parallel_min CHECK ((max_parallel >= 1)),
    CONSTRAINT patch_rollback_dispatch_runs_state_vocab CHECK (((state)::text = ANY ((ARRAY['pending'::character varying, 'running'::character varying, 'paused'::character varying, 'succeeded'::character varying, 'failed'::character varying, 'canceled'::character varying])::text[])))
);


--
-- Name: patch_rollback_dispatch_runs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.patch_rollback_dispatch_runs_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: patch_rollback_dispatch_runs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.patch_rollback_dispatch_runs_id_seq OWNED BY public.patch_rollback_dispatch_runs.id;


--
-- Name: patch_update_execution_host_packages; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.patch_update_execution_host_packages (
    id integer NOT NULL,
    execution_host_id integer NOT NULL,
    package_name character varying(255) NOT NULL,
    requested_version_snapshot character varying(255),
    installed_version_before character varying(255),
    installed_version_after character varying(255),
    package_manager_family_snapshot character varying(16) NOT NULL,
    outcome character varying(32) NOT NULL,
    error_code character varying(64),
    details jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT patch_update_execution_host_packages_family_vocab CHECK (((package_manager_family_snapshot)::text = ANY ((ARRAY['apt'::character varying, 'dnf'::character varying, 'unknown'::character varying])::text[]))),
    CONSTRAINT patch_update_execution_host_packages_outcome_vocab CHECK (((outcome)::text = ANY ((ARRAY['succeeded'::character varying, 'failed'::character varying, 'skipped'::character varying, 'unknown'::character varying])::text[])))
);


--
-- Name: patch_update_execution_host_packages_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.patch_update_execution_host_packages_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: patch_update_execution_host_packages_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.patch_update_execution_host_packages_id_seq OWNED BY public.patch_update_execution_host_packages.id;


--
-- Name: patch_update_execution_hosts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.patch_update_execution_hosts (
    id integer NOT NULL,
    execution_id integer NOT NULL,
    plan_host_id integer NOT NULL,
    system_id_snapshot integer,
    system_hostname_snapshot character varying(255),
    wave_index integer NOT NULL,
    state character varying(32) NOT NULL,
    selected_package_count integer DEFAULT 0 NOT NULL,
    skip_reasons jsonb DEFAULT '[]'::jsonb NOT NULL,
    error_details jsonb DEFAULT '{}'::jsonb NOT NULL,
    started_at timestamp without time zone,
    completed_at timestamp without time zone,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT patch_update_execution_hosts_selected_count_nonneg CHECK ((selected_package_count >= 0)),
    CONSTRAINT patch_update_execution_hosts_state_vocab CHECK (((state)::text = ANY ((ARRAY['pending'::character varying, 'running'::character varying, 'succeeded'::character varying, 'failed'::character varying, 'skipped'::character varying, 'paused'::character varying, 'canceled'::character varying])::text[]))),
    CONSTRAINT patch_update_execution_hosts_wave_index_nonneg CHECK ((wave_index >= 0))
);


--
-- Name: patch_update_execution_hosts_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.patch_update_execution_hosts_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: patch_update_execution_hosts_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.patch_update_execution_hosts_id_seq OWNED BY public.patch_update_execution_hosts.id;


--
-- Name: patch_update_execution_reboots; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.patch_update_execution_reboots (
    id integer NOT NULL,
    execution_id integer NOT NULL,
    execution_host_id integer NOT NULL,
    plan_id_snapshot integer NOT NULL,
    system_id_snapshot integer,
    system_hostname_snapshot character varying(255),
    wave_index integer NOT NULL,
    state character varying(32) NOT NULL,
    reboot_policy_snapshot character varying(32) NOT NULL,
    reboot_window_id_snapshot integer,
    reboot_required_fact boolean,
    decision_code character varying(64) NOT NULL,
    decision_details jsonb DEFAULT '{}'::jsonb NOT NULL,
    scheduled_for_at timestamp without time zone,
    started_at timestamp without time zone,
    completed_at timestamp without time zone,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    transport_kind character varying(16),
    command_snapshot text,
    exit_signal_kind character varying(32),
    dispatch_details jsonb DEFAULT '{}'::jsonb NOT NULL,
    verified_at timestamp without time zone,
    verification_details jsonb DEFAULT '{}'::jsonb NOT NULL,
    CONSTRAINT patch_update_execution_reboots_exit_signal_kind_vocab CHECK (((exit_signal_kind IS NULL) OR ((exit_signal_kind)::text = ANY ((ARRAY['exit_zero'::character varying, 'connection_lost_clean'::character varying, 'non_zero'::character varying, 'timeout'::character varying, 'transport_error'::character varying, 'transport_unavailable'::character varying])::text[])))),
    CONSTRAINT patch_update_execution_reboots_policy_vocab CHECK (((reboot_policy_snapshot)::text = ANY ((ARRAY['never'::character varying, 'if_required'::character varying, 'always'::character varying, 'unknown'::character varying])::text[]))),
    CONSTRAINT patch_update_execution_reboots_state_vocab CHECK (((state)::text = ANY ((ARRAY['not_required'::character varying, 'pending'::character varying, 'scheduled'::character varying, 'rebooting'::character varying, 'verifying'::character varying, 'healthy'::character varying, 'failed'::character varying, 'skipped'::character varying])::text[]))),
    CONSTRAINT patch_update_execution_reboots_wave_index_nonneg CHECK ((wave_index >= 0))
);


--
-- Name: patch_update_execution_reboots_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.patch_update_execution_reboots_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: patch_update_execution_reboots_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.patch_update_execution_reboots_id_seq OWNED BY public.patch_update_execution_reboots.id;


--
-- Name: patch_update_execution_rollback_approvals; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.patch_update_execution_rollback_approvals (
    id integer NOT NULL,
    rollback_id integer NOT NULL,
    approval_id integer NOT NULL,
    requested_by integer NOT NULL,
    requested_at timestamp without time zone NOT NULL,
    frozen_plan_snapshot jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


--
-- Name: patch_update_execution_rollback_approvals_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.patch_update_execution_rollback_approvals_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: patch_update_execution_rollback_approvals_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.patch_update_execution_rollback_approvals_id_seq OWNED BY public.patch_update_execution_rollback_approvals.id;


--
-- Name: patch_update_execution_rollback_hosts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.patch_update_execution_rollback_hosts (
    id integer NOT NULL,
    rollback_id integer NOT NULL,
    execution_host_id integer NOT NULL,
    plan_host_id_snapshot integer NOT NULL,
    system_id_snapshot integer,
    system_hostname_snapshot character varying(255),
    wave_index integer NOT NULL,
    execution_host_state_snapshot character varying(32) NOT NULL,
    state character varying(32) NOT NULL,
    refusal_reason character varying(64),
    refusal_details jsonb DEFAULT '{}'::jsonb NOT NULL,
    content_profile_snapshot jsonb DEFAULT '{}'::jsonb NOT NULL,
    package_summary jsonb DEFAULT '{}'::jsonb NOT NULL,
    evaluated_at timestamp without time zone NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT patch_update_execution_rollback_hosts_state_vocab CHECK (((state)::text = ANY ((ARRAY['feasible'::character varying, 'partial_feasible'::character varying, 'infeasible'::character varying])::text[]))),
    CONSTRAINT patch_update_execution_rollback_hosts_wave_index_nonneg CHECK ((wave_index >= 0))
);


--
-- Name: patch_update_execution_rollback_hosts_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.patch_update_execution_rollback_hosts_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: patch_update_execution_rollback_hosts_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.patch_update_execution_rollback_hosts_id_seq OWNED BY public.patch_update_execution_rollback_hosts.id;


--
-- Name: patch_update_execution_rollback_packages; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.patch_update_execution_rollback_packages (
    id integer NOT NULL,
    rollback_host_id integer NOT NULL,
    execution_host_package_id integer,
    package_name character varying(255) NOT NULL,
    package_manager_family_snapshot character varying(16) NOT NULL,
    installed_version_before_snapshot character varying(255),
    installed_version_after_snapshot character varying(255),
    requested_version_snapshot character varying(255),
    target_rollback_version character varying(255),
    package_outcome_snapshot character varying(32) NOT NULL,
    state character varying(32) NOT NULL,
    refusal_reason character varying(64),
    refusal_details jsonb DEFAULT '{}'::jsonb NOT NULL,
    content_evidence jsonb DEFAULT '{}'::jsonb NOT NULL,
    evaluated_at timestamp without time zone NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    command_plan jsonb,
    CONSTRAINT patch_update_execution_rollback_packages_family_vocab CHECK (((package_manager_family_snapshot)::text = ANY ((ARRAY['apt'::character varying, 'dnf'::character varying, 'unknown'::character varying])::text[]))),
    CONSTRAINT patch_update_execution_rollback_packages_state_vocab CHECK (((state)::text = ANY ((ARRAY['feasible'::character varying, 'infeasible'::character varying])::text[])))
);


--
-- Name: patch_update_execution_rollback_packages_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.patch_update_execution_rollback_packages_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: patch_update_execution_rollback_packages_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.patch_update_execution_rollback_packages_id_seq OWNED BY public.patch_update_execution_rollback_packages.id;


--
-- Name: patch_update_execution_rollbacks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.patch_update_execution_rollbacks (
    id integer NOT NULL,
    execution_id integer NOT NULL,
    plan_id_snapshot integer NOT NULL,
    execution_state_snapshot character varying(32) NOT NULL,
    state character varying(32) NOT NULL,
    refusal_reason character varying(64),
    refusal_details jsonb DEFAULT '{}'::jsonb NOT NULL,
    feasibility_summary jsonb DEFAULT '{}'::jsonb NOT NULL,
    evaluated_at timestamp without time zone NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT patch_update_execution_rollbacks_state_vocab CHECK (((state)::text = ANY ((ARRAY['evaluated'::character varying, 'refused'::character varying])::text[])))
);


--
-- Name: patch_update_execution_rollbacks_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.patch_update_execution_rollbacks_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: patch_update_execution_rollbacks_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.patch_update_execution_rollbacks_id_seq OWNED BY public.patch_update_execution_rollbacks.id;


--
-- Name: patch_update_executions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.patch_update_executions (
    id integer NOT NULL,
    plan_id integer NOT NULL,
    state character varying(32) NOT NULL,
    started_by integer NOT NULL,
    started_at timestamp without time zone NOT NULL,
    completed_at timestamp without time zone,
    paused_at timestamp without time zone,
    canceled_at timestamp without time zone,
    max_parallel_per_wave integer NOT NULL,
    failure_threshold_percent integer,
    pause_reason text,
    cancel_reason text,
    plan_state_snapshot character varying(32) NOT NULL,
    policy_snapshot jsonb DEFAULT '{}'::jsonb NOT NULL,
    execution_config_snapshot jsonb DEFAULT '{}'::jsonb NOT NULL,
    progress_summary jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT patch_update_executions_parallel_min CHECK ((max_parallel_per_wave >= 1)),
    CONSTRAINT patch_update_executions_state_vocab CHECK (((state)::text = ANY ((ARRAY['pending'::character varying, 'running'::character varying, 'paused'::character varying, 'succeeded'::character varying, 'failed'::character varying, 'canceled'::character varying])::text[]))),
    CONSTRAINT patch_update_executions_threshold_range CHECK (((failure_threshold_percent IS NULL) OR ((failure_threshold_percent >= 0) AND (failure_threshold_percent <= 100))))
);


--
-- Name: patch_update_executions_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.patch_update_executions_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: patch_update_executions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.patch_update_executions_id_seq OWNED BY public.patch_update_executions.id;


--
-- Name: patch_update_plan_approvals; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.patch_update_plan_approvals (
    id integer NOT NULL,
    plan_id integer NOT NULL,
    approval_id integer NOT NULL,
    requested_by integer NOT NULL,
    requested_at timestamp without time zone NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


--
-- Name: patch_update_plan_approvals_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.patch_update_plan_approvals_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: patch_update_plan_approvals_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.patch_update_plan_approvals_id_seq OWNED BY public.patch_update_plan_approvals.id;


--
-- Name: patch_update_plan_hosts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.patch_update_plan_hosts (
    id integer NOT NULL,
    plan_id integer NOT NULL,
    system_id integer,
    system_hostname_snapshot character varying(255),
    policy_id_snapshot integer,
    policy_slug_snapshot character varying(64),
    policy_resolution_kind character varying(32) NOT NULL,
    ring_id_snapshot integer,
    ring_slug_snapshot character varying(64),
    ring_name_snapshot character varying(128),
    ring_sort_order_snapshot integer,
    ring_source_tier character varying(32),
    ring_resolution_status character varying(32) NOT NULL,
    wave_index integer NOT NULL,
    content_profile_state character varying(32) NOT NULL,
    content_profile_id_snapshot integer,
    content_profile_slug_snapshot character varying(64),
    content_profile_display_name_snapshot character varying(128),
    content_profile_package_family_snapshot character varying(8),
    content_profile_conflict_snapshot jsonb DEFAULT '[]'::jsonb NOT NULL,
    state character varying(32) NOT NULL,
    block_reasons jsonb DEFAULT '[]'::jsonb NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    selection_summary jsonb,
    preflight_summary jsonb,
    CONSTRAINT patch_update_plan_hosts_content_profile_state_vocab CHECK (((content_profile_state)::text = ANY ((ARRAY['resolved'::character varying, 'no_profile'::character varying, 'conflict'::character varying])::text[]))),
    CONSTRAINT patch_update_plan_hosts_policy_resolution_kind_vocab CHECK (((policy_resolution_kind)::text = ANY ((ARRAY['direct_host'::character varying, 'static_group'::character varying, 'smart_group'::character varying, 'fleet_default'::character varying, 'no_policy'::character varying])::text[]))),
    CONSTRAINT patch_update_plan_hosts_ring_resolution_status_vocab CHECK (((ring_resolution_status)::text = ANY ((ARRAY['resolved'::character varying, 'no_ring'::character varying, 'conflict'::character varying, 'not_applicable'::character varying])::text[]))),
    CONSTRAINT patch_update_plan_hosts_state_vocab CHECK (((state)::text = ANY ((ARRAY['planned'::character varying, 'blocked'::character varying])::text[]))),
    CONSTRAINT patch_update_plan_hosts_wave_index_nonneg CHECK ((wave_index >= 0))
);


--
-- Name: patch_update_plan_hosts_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.patch_update_plan_hosts_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: patch_update_plan_hosts_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.patch_update_plan_hosts_id_seq OWNED BY public.patch_update_plan_hosts.id;


--
-- Name: patch_update_plan_preflight_snapshots; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.patch_update_plan_preflight_snapshots (
    id integer NOT NULL,
    plan_host_id integer NOT NULL,
    package_name character varying(255) NOT NULL,
    installed_version_at_preflight character varying(255),
    package_manager_family_snapshot character varying(16) NOT NULL,
    content_availability_state character varying(32) NOT NULL,
    availability_details jsonb DEFAULT '{}'::jsonb NOT NULL,
    evaluated_at timestamp without time zone NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT patch_update_plan_preflight_snapshots_family_vocab CHECK (((package_manager_family_snapshot)::text = ANY ((ARRAY['apt'::character varying, 'dnf'::character varying, 'unknown'::character varying])::text[]))),
    CONSTRAINT patch_update_plan_preflight_snapshots_state_vocab CHECK (((content_availability_state)::text = ANY ((ARRAY['available'::character varying, 'unavailable'::character varying, 'profile_missing'::character varying, 'not_applicable'::character varying])::text[])))
);


--
-- Name: patch_update_plan_preflight_snapshots_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.patch_update_plan_preflight_snapshots_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: patch_update_plan_preflight_snapshots_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.patch_update_plan_preflight_snapshots_id_seq OWNED BY public.patch_update_plan_preflight_snapshots.id;


--
-- Name: patch_update_plan_selected_packages; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.patch_update_plan_selected_packages (
    id integer NOT NULL,
    plan_host_id integer NOT NULL,
    package_name character varying(255) NOT NULL,
    installed_version_snapshot character varying(255),
    available_version_snapshot character varying(255),
    advisory_id_snapshot integer,
    advisory_source_kind_snapshot character varying(32),
    advisory_class_snapshot character varying(32),
    advisory_severity_snapshot character varying(32),
    selection_reason character varying(48) NOT NULL,
    state character varying(32) NOT NULL,
    details jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT patch_update_plan_selected_packages_reason_vocab CHECK (((selection_reason)::text = ANY ((ARRAY['policy_full'::character varying, 'policy_security_advisory'::character varying, 'policy_allowlist_match'::character varying, 'policy_denylist_excluded'::character varying, 'policy_denylist_default_select'::character varying, 'no_available_update'::character varying, 'inventory_missing'::character varying])::text[]))),
    CONSTRAINT patch_update_plan_selected_packages_state_vocab CHECK (((state)::text = ANY ((ARRAY['selected'::character varying, 'excluded'::character varying, 'unresolvable'::character varying])::text[])))
);


--
-- Name: patch_update_plan_selected_packages_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.patch_update_plan_selected_packages_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: patch_update_plan_selected_packages_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.patch_update_plan_selected_packages_id_seq OWNED BY public.patch_update_plan_selected_packages.id;


--
-- Name: patch_update_plans; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.patch_update_plans (
    id integer NOT NULL,
    policy_id integer,
    name character varying(128) NOT NULL,
    description text,
    state character varying(32) NOT NULL,
    scheduled_start_at timestamp without time zone,
    maintenance_window_id integer,
    reboot_window_id integer,
    policy_snapshot jsonb DEFAULT '{}'::jsonb NOT NULL,
    ring_sequence_snapshot jsonb DEFAULT '[]'::jsonb NOT NULL,
    request_snapshot jsonb DEFAULT '{}'::jsonb NOT NULL,
    block_reasons jsonb DEFAULT '[]'::jsonb NOT NULL,
    created_by integer NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    archived_at timestamp without time zone,
    archived_by integer,
    archive_reason text,
    CONSTRAINT patch_update_plans_state_vocab CHECK (((state)::text = ANY ((ARRAY['draft'::character varying, 'awaiting_approval'::character varying, 'approved'::character varying, 'scheduled'::character varying, 'blocked'::character varying, 'superseded'::character varying, 'canceled'::character varying])::text[])))
);


--
-- Name: patch_update_plans_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.patch_update_plans_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: patch_update_plans_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.patch_update_plans_id_seq OWNED BY public.patch_update_plans.id;


--
-- Name: recordings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.recordings (
    id integer NOT NULL,
    session_id integer NOT NULL,
    user_id integer,
    system_id integer,
    file_path text NOT NULL,
    size_bytes bigint DEFAULT '0'::bigint NOT NULL,
    frame_count integer DEFAULT 0 NOT NULL,
    started_at timestamp without time zone DEFAULT now() NOT NULL,
    ended_at timestamp without time zone,
    retention_expires_at timestamp without time zone NOT NULL,
    status character varying(20) DEFAULT 'active'::character varying NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: recordings_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.recordings_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: recordings_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.recordings_id_seq OWNED BY public.recordings.id;


--
-- Name: refresh_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.refresh_tokens (
    id integer NOT NULL,
    token character varying NOT NULL,
    user_id integer NOT NULL,
    is_valid boolean NOT NULL,
    created_at timestamp without time zone,
    expires_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL
);


--
-- Name: refresh_tokens_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.refresh_tokens_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: refresh_tokens_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.refresh_tokens_id_seq OWNED BY public.refresh_tokens.id;


--
-- Name: repo_sources; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.repo_sources (
    id integer NOT NULL,
    system_id integer NOT NULL,
    name character varying(255) NOT NULL,
    url text NOT NULL,
    repo_type character varying(50) NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    file_path character varying(500),
    gpg_key_url text,
    components character varying(500),
    distribution character varying(255),
    created_at timestamp without time zone,
    updated_at timestamp without time zone
);


--
-- Name: repo_sources_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.repo_sources_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: repo_sources_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.repo_sources_id_seq OWNED BY public.repo_sources.id;


--
-- Name: report_runs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.report_runs (
    id integer NOT NULL,
    report_kind character varying(64) NOT NULL,
    triggered_by character varying(32) DEFAULT 'user'::character varying NOT NULL,
    triggered_by_user_id integer,
    triggered_by_username character varying(255),
    format character varying(16),
    filters_snapshot jsonb DEFAULT '{}'::jsonb NOT NULL,
    row_count integer,
    state character varying(16) DEFAULT 'started'::character varying NOT NULL,
    error_message character varying(2048),
    started_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    completed_at timestamp without time zone,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT report_runs_format_vocab CHECK (((format IS NULL) OR ((format)::text = ANY ((ARRAY['csv'::character varying, 'json'::character varying, 'jsonl'::character varying])::text[])))),
    CONSTRAINT report_runs_report_kind_vocab CHECK (((report_kind)::text = ANY ((ARRAY['patch_executions'::character varying, 'compliance_remediation_requests'::character varying, 'compliance_evidence'::character varying, 'patch_update_plans'::character varying, 'patch_reboot_queues'::character varying, 'patch_rollback_runs'::character varying, 'compliance_remediation_plans'::character varying, 'compliance_remediation_executions'::character varying, 'package_outdated'::character varying, 'package_compliance'::character varying])::text[]))),
    CONSTRAINT report_runs_row_count_nonneg CHECK (((row_count IS NULL) OR (row_count >= 0))),
    CONSTRAINT report_runs_state_vocab CHECK (((state)::text = ANY ((ARRAY['started'::character varying, 'succeeded'::character varying, 'failed'::character varying])::text[]))),
    CONSTRAINT report_runs_triggered_by_vocab CHECK (((triggered_by)::text = ANY ((ARRAY['user'::character varying, 'system_scheduled'::character varying])::text[])))
);


--
-- Name: report_runs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.report_runs_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: report_runs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.report_runs_id_seq OWNED BY public.report_runs.id;


--
-- Name: report_schedules; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.report_schedules (
    id integer NOT NULL,
    name character varying(128) NOT NULL,
    report_kind character varying(64) NOT NULL,
    cadence character varying(16) NOT NULL,
    filters_snapshot jsonb DEFAULT '{}'::jsonb NOT NULL,
    format character varying(16) DEFAULT 'csv'::character varying NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    next_run_at timestamp without time zone,
    last_run_at timestamp without time zone,
    last_run_id integer,
    last_run_state character varying(16),
    created_by integer,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT report_schedules_cadence_vocab CHECK (((cadence)::text = ANY ((ARRAY['daily'::character varying, 'weekly'::character varying, 'monthly'::character varying])::text[]))),
    CONSTRAINT report_schedules_format_vocab CHECK (((format)::text = ANY ((ARRAY['csv'::character varying, 'json'::character varying])::text[]))),
    CONSTRAINT report_schedules_last_run_state_vocab CHECK (((last_run_state IS NULL) OR ((last_run_state)::text = ANY ((ARRAY['started'::character varying, 'succeeded'::character varying, 'failed'::character varying])::text[])))),
    CONSTRAINT report_schedules_report_kind_vocab CHECK (((report_kind)::text = ANY ((ARRAY['patch_executions'::character varying, 'compliance_remediation_requests'::character varying, 'compliance_evidence'::character varying, 'patch_update_plans'::character varying, 'patch_reboot_queues'::character varying, 'patch_rollback_runs'::character varying, 'compliance_remediation_plans'::character varying, 'compliance_remediation_executions'::character varying, 'package_outdated'::character varying, 'package_compliance'::character varying])::text[])))
);


--
-- Name: report_schedules_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.report_schedules_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: report_schedules_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.report_schedules_id_seq OWNED BY public.report_schedules.id;


--
-- Name: revocation_work; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.revocation_work (
    id integer NOT NULL,
    reason character varying(48) NOT NULL,
    source character varying(128),
    user_id integer,
    system_id integer,
    login character varying(100),
    status character varying(16) DEFAULT 'pending'::character varying NOT NULL,
    attempt_count integer DEFAULT 0 NOT NULL,
    next_retry_at timestamp without time zone,
    last_error text,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL,
    completed_at timestamp without time zone
);


--
-- Name: revocation_work_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.revocation_work_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: revocation_work_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.revocation_work_id_seq OWNED BY public.revocation_work.id;


--
-- Name: role; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.role (
    id integer NOT NULL,
    name character varying NOT NULL,
    description character varying,
    created_at timestamp without time zone,
    updated_at timestamp without time zone
);


--
-- Name: role_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.role_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: role_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.role_id_seq OWNED BY public.role.id;


--
-- Name: saved_views; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.saved_views (
    id integer NOT NULL,
    name character varying(100) NOT NULL,
    user_id integer NOT NULL,
    filters text NOT NULL,
    is_default boolean DEFAULT false NOT NULL,
    is_shared boolean DEFAULT false NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: saved_views_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.saved_views_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: saved_views_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.saved_views_id_seq OWNED BY public.saved_views.id;


--
-- Name: scheduler_job_locks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.scheduler_job_locks (
    id integer NOT NULL,
    job_id character varying(128) NOT NULL,
    last_fired_at timestamp without time zone NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


--
-- Name: scheduler_job_locks_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.scheduler_job_locks_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: scheduler_job_locks_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.scheduler_job_locks_id_seq OWNED BY public.scheduler_job_locks.id;


--
-- Name: session_approvals; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.session_approvals (
    id integer NOT NULL,
    requester_id integer NOT NULL,
    system_id integer NOT NULL,
    fleet_role_id integer NOT NULL,
    login character varying(100) NOT NULL,
    reason text,
    state character varying(20) DEFAULT 'pending'::character varying NOT NULL,
    approver_id integer,
    decision_reason text,
    decided_at timestamp without time zone,
    expires_at timestamp without time zone,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: session_approvals_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.session_approvals_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: session_approvals_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.session_approvals_id_seq OWNED BY public.session_approvals.id;


--
-- Name: session_locks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.session_locks (
    id integer NOT NULL,
    subject_user_id integer,
    subject_app_role_id integer,
    reason text NOT NULL,
    created_by integer,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    released_at timestamp without time zone,
    released_by integer,
    updated_at timestamp without time zone DEFAULT now() NOT NULL,
    CONSTRAINT ck_session_locks_subject_xor CHECK (((subject_user_id IS NOT NULL) <> (subject_app_role_id IS NOT NULL)))
);


--
-- Name: session_locks_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.session_locks_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: session_locks_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.session_locks_id_seq OWNED BY public.session_locks.id;


--
-- Name: sessions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sessions (
    id integer NOT NULL,
    user_id integer NOT NULL,
    system_id integer NOT NULL,
    fleet_role_id integer,
    login character varying(100) NOT NULL,
    cert_serial character varying(255),
    client_ip character varying(64),
    status character varying(20) DEFAULT 'opening'::character varying NOT NULL,
    close_reason text,
    started_at timestamp without time zone DEFAULT now() NOT NULL,
    last_activity_at timestamp without time zone,
    ended_at timestamp without time zone,
    max_expires_at timestamp without time zone NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL,
    transport character varying(8),
    recording_retention_days integer
);


--
-- Name: sessions_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.sessions_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: sessions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.sessions_id_seq OWNED BY public.sessions.id;


--
-- Name: smart_group_content_profile_subscriptions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.smart_group_content_profile_subscriptions (
    id integer NOT NULL,
    smart_group_id integer NOT NULL,
    profile_id integer NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);


--
-- Name: smart_group_content_profile_subscriptions_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.smart_group_content_profile_subscriptions_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: smart_group_content_profile_subscriptions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.smart_group_content_profile_subscriptions_id_seq OWNED BY public.smart_group_content_profile_subscriptions.id;


--
-- Name: smart_group_memberships; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.smart_group_memberships (
    id integer NOT NULL,
    smart_group_id integer NOT NULL,
    system_id integer NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: smart_group_memberships_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.smart_group_memberships_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: smart_group_memberships_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.smart_group_memberships_id_seq OWNED BY public.smart_group_memberships.id;


--
-- Name: smart_groups; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.smart_groups (
    id integer NOT NULL,
    name character varying(100) NOT NULL,
    description text,
    rule_json text NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    created_by integer,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: smart_groups_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.smart_groups_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: smart_groups_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.smart_groups_id_seq OWNED BY public.smart_groups.id;


--
-- Name: ssh_host_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ssh_host_keys (
    id integer NOT NULL,
    system_id integer NOT NULL,
    hostname character varying(255) NOT NULL,
    key_type character varying(50) NOT NULL,
    public_key text NOT NULL,
    fingerprint character varying(255) NOT NULL,
    verified boolean,
    first_seen timestamp without time zone,
    last_seen timestamp without time zone,
    created_at timestamp without time zone,
    updated_at timestamp without time zone
);


--
-- Name: ssh_host_keys_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ssh_host_keys_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ssh_host_keys_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ssh_host_keys_id_seq OWNED BY public.ssh_host_keys.id;


--
-- Name: ssh_identity_settings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ssh_identity_settings (
    id integer NOT NULL,
    user_cert_ttl_seconds integer DEFAULT 300 NOT NULL,
    default_principal character varying(100),
    ca_identifier character varying(100),
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: ssh_identity_settings_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ssh_identity_settings_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ssh_identity_settings_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ssh_identity_settings_id_seq OWNED BY public.ssh_identity_settings.id;


--
-- Name: ssh_security_logs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ssh_security_logs (
    id integer NOT NULL,
    system_id integer NOT NULL,
    event_type character varying(50) NOT NULL,
    event_details text,
    source_ip character varying(50),
    username character varying(255),
    success boolean,
    "timestamp" timestamp without time zone,
    created_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone NOT NULL
);


--
-- Name: ssh_security_logs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ssh_security_logs_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ssh_security_logs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ssh_security_logs_id_seq OWNED BY public.ssh_security_logs.id;


--
-- Name: ssh_security_policies; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ssh_security_policies (
    id integer NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    max_auth_tries integer,
    connection_timeout integer,
    idle_timeout integer,
    require_host_key_verification boolean,
    minimum_key_size integer,
    allowed_auth_methods character varying(255),
    allowed_ciphers character varying(255),
    allowed_macs character varying(255),
    allowed_kex character varying(255),
    log_commands boolean,
    log_file_transfers boolean,
    created_at timestamp without time zone,
    updated_at timestamp without time zone,
    created_by integer NOT NULL
);


--
-- Name: ssh_security_policies_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ssh_security_policies_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ssh_security_policies_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ssh_security_policies_id_seq OWNED BY public.ssh_security_policies.id;


--
-- Name: system_audits; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.system_audits (
    id integer NOT NULL,
    system_id integer,
    audit_type character varying(50) NOT NULL,
    changed_by integer NOT NULL,
    changed_at timestamp without time zone NOT NULL,
    old_value text,
    new_value text,
    operation character varying(50) NOT NULL,
    created_at timestamp without time zone,
    updated_at timestamp without time zone
);


--
-- Name: system_audits_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.system_audits_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: system_audits_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.system_audits_id_seq OWNED BY public.system_audits.id;


--
-- Name: system_metadata; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.system_metadata (
    id integer NOT NULL,
    system_id integer NOT NULL,
    cpu_arch character varying(50),
    cpu_cores integer,
    memory_total bigint,
    disk_total bigint,
    environment_type character varying(50),
    maintenance_window character varying(100),
    owner_contact character varying(255),
    location character varying(255),
    ssh_port integer,
    last_connection timestamp without time zone,
    connection_status character varying(50),
    created_at timestamp without time zone,
    updated_at timestamp without time zone,
    consecutive_failures integer DEFAULT 0 NOT NULL,
    transport_failures integer DEFAULT 0 NOT NULL,
    transport_cooldown_until timestamp without time zone,
    last_transport_error character varying(500)
);


--
-- Name: system_metadata_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.system_metadata_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: system_metadata_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.system_metadata_id_seq OWNED BY public.system_metadata.id;


--
-- Name: system_tag; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.system_tag (
    system_id integer NOT NULL,
    tag_id integer NOT NULL,
    created_at timestamp without time zone
);


--
-- Name: systems; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.systems (
    id integer NOT NULL,
    hostname character varying(255) NOT NULL,
    ip_address inet NOT NULL,
    distro_id integer NOT NULL,
    os_version character varying(50) NOT NULL,
    last_audited timestamp without time zone,
    status character varying(50) NOT NULL,
    group_id integer NOT NULL,
    credentials_id integer NOT NULL,
    ssh_security_policy_id integer,
    registered_at timestamp without time zone,
    registered_by integer,
    update_policy character varying(50),
    last_successful_update timestamp without time zone,
    created_at timestamp without time zone,
    updated_at timestamp without time zone,
    ca_trust_deployed boolean DEFAULT false NOT NULL,
    ca_trust_deployed_at timestamp without time zone,
    principals_hook_deployed boolean DEFAULT false NOT NULL,
    principals_hook_deployed_at timestamp without time zone,
    agent_status public.agent_status_enum DEFAULT 'not_enrolled'::public.agent_status_enum NOT NULL,
    agent_cert_serial character varying(128),
    agent_cert_fingerprint character varying(128),
    agent_cert_expires_at timestamp without time zone,
    agent_revoked_at timestamp without time zone,
    agent_status_reason character varying(255),
    agent_revocation_reason character varying(255),
    agent_last_seen_at timestamp without time zone,
    agent_version character varying(32),
    transport_preference public.transport_preference_enum DEFAULT 'auto'::public.transport_preference_enum NOT NULL
);


--
-- Name: systems_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.systems_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: systems_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.systems_id_seq OWNED BY public.systems.id;


--
-- Name: tags; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tags (
    id integer NOT NULL,
    name character varying(100) NOT NULL,
    color character varying(7) DEFAULT '#6B7280'::character varying NOT NULL,
    created_by integer NOT NULL,
    created_at timestamp without time zone,
    updated_at timestamp without time zone
);


--
-- Name: tags_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.tags_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: tags_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.tags_id_seq OWNED BY public.tags.id;


--
-- Name: totp_challenges; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.totp_challenges (
    id integer NOT NULL,
    user_id integer NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    expires_at timestamp without time zone NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: totp_challenges_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.totp_challenges_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: totp_challenges_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.totp_challenges_id_seq OWNED BY public.totp_challenges.id;


--
-- Name: user; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public."user" (
    id integer NOT NULL,
    username character varying NOT NULL,
    email character varying NOT NULL,
    hashed_password character varying NOT NULL,
    is_active boolean,
    oidc_sub character varying,
    created_at timestamp without time zone,
    updated_at timestamp without time zone,
    oidc_issuer character varying,
    totp_secret character varying(64),
    totp_enrolled_at timestamp without time zone,
    totp_recovery_codes text
);


--
-- Name: user_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.user_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: user_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.user_id_seq OWNED BY public."user".id;


--
-- Name: user_role; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_role (
    user_id integer NOT NULL,
    role_id integer NOT NULL,
    created_at timestamp without time zone,
    updated_at timestamp without time zone
);


--
-- Name: vault_config; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.vault_config (
    id integer NOT NULL,
    is_internal boolean NOT NULL,
    server_url character varying(255),
    is_active boolean NOT NULL,
    created_at timestamp without time zone,
    updated_at timestamp without time zone,
    created_by integer,
    last_health_check timestamp without time zone,
    health_status character varying(50)
);


--
-- Name: vault_config_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.vault_config_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: vault_config_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.vault_config_id_seq OWNED BY public.vault_config.id;


--
-- Name: access_bindings id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.access_bindings ALTER COLUMN id SET DEFAULT nextval('public.access_bindings_id_seq'::regclass);


--
-- Name: access_grants id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.access_grants ALTER COLUMN id SET DEFAULT nextval('public.access_grants_id_seq'::regclass);


--
-- Name: access_requests id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.access_requests ALTER COLUMN id SET DEFAULT nextval('public.access_requests_id_seq'::regclass);


--
-- Name: access_review_items id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.access_review_items ALTER COLUMN id SET DEFAULT nextval('public.access_review_items_id_seq'::regclass);


--
-- Name: access_reviews id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.access_reviews ALTER COLUMN id SET DEFAULT nextval('public.access_reviews_id_seq'::regclass);


--
-- Name: activation_token_redemptions id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.activation_token_redemptions ALTER COLUMN id SET DEFAULT nextval('public.activation_token_redemptions_id_seq'::regclass);


--
-- Name: activation_tokens id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.activation_tokens ALTER COLUMN id SET DEFAULT nextval('public.activation_tokens_id_seq'::regclass);


--
-- Name: airgap_bundle_signing_keys id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.airgap_bundle_signing_keys ALTER COLUMN id SET DEFAULT nextval('public.airgap_bundle_signing_keys_id_seq'::regclass);


--
-- Name: airgap_bundles id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.airgap_bundles ALTER COLUMN id SET DEFAULT nextval('public.airgap_bundles_id_seq'::regclass);


--
-- Name: airgap_import_trust_keys id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.airgap_import_trust_keys ALTER COLUMN id SET DEFAULT nextval('public.airgap_import_trust_keys_id_seq'::regclass);


--
-- Name: airgap_imports id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.airgap_imports ALTER COLUMN id SET DEFAULT nextval('public.airgap_imports_id_seq'::regclass);


--
-- Name: alert_configs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alert_configs ALTER COLUMN id SET DEFAULT nextval('public.alert_configs_id_seq'::regclass);


--
-- Name: alert_history id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alert_history ALTER COLUMN id SET DEFAULT nextval('public.alert_history_id_seq'::regclass);


--
-- Name: app_settings id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.app_settings ALTER COLUMN id SET DEFAULT nextval('public.app_settings_id_seq'::regclass);


--
-- Name: audit_events id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_events ALTER COLUMN id SET DEFAULT nextval('public.audit_events_id_seq'::regclass);


--
-- Name: audit_sink_deliveries id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_sink_deliveries ALTER COLUMN id SET DEFAULT nextval('public.audit_sink_deliveries_id_seq'::regclass);


--
-- Name: audit_sinks id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_sinks ALTER COLUMN id SET DEFAULT nextval('public.audit_sinks_id_seq'::regclass);


--
-- Name: baseline_checks id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.baseline_checks ALTER COLUMN id SET DEFAULT nextval('public.baseline_checks_id_seq'::regclass);


--
-- Name: baselines id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.baselines ALTER COLUMN id SET DEFAULT nextval('public.baselines_id_seq'::regclass);


--
-- Name: ca_rotations id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ca_rotations ALTER COLUMN id SET DEFAULT nextval('public.ca_rotations_id_seq'::regclass);


--
-- Name: command_approval_votes id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.command_approval_votes ALTER COLUMN id SET DEFAULT nextval('public.command_approval_votes_id_seq'::regclass);


--
-- Name: command_approvals id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.command_approvals ALTER COLUMN id SET DEFAULT nextval('public.command_approvals_id_seq'::regclass);


--
-- Name: command_distro_mapping id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.command_distro_mapping ALTER COLUMN id SET DEFAULT nextval('public.command_distro_mapping_id_seq'::regclass);


--
-- Name: command_execution_metrics id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.command_execution_metrics ALTER COLUMN id SET DEFAULT nextval('public.command_execution_metrics_id_seq'::regclass);


--
-- Name: command_execution_policies id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.command_execution_policies ALTER COLUMN id SET DEFAULT nextval('public.command_execution_policies_id_seq'::regclass);


--
-- Name: command_execution_queue id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.command_execution_queue ALTER COLUMN id SET DEFAULT nextval('public.command_execution_queue_id_seq'::regclass);


--
-- Name: command_execution_results id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.command_execution_results ALTER COLUMN id SET DEFAULT nextval('public.command_execution_results_id_seq'::regclass);


--
-- Name: command_execution_system_policies id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.command_execution_system_policies ALTER COLUMN id SET DEFAULT nextval('public.command_execution_system_policies_id_seq'::regclass);


--
-- Name: command_execution_user_policies id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.command_execution_user_policies ALTER COLUMN id SET DEFAULT nextval('public.command_execution_user_policies_id_seq'::regclass);


--
-- Name: command_resource_limits id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.command_resource_limits ALTER COLUMN id SET DEFAULT nextval('public.command_resource_limits_id_seq'::regclass);


--
-- Name: command_template_distros id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.command_template_distros ALTER COLUMN id SET DEFAULT nextval('public.command_template_distros_id_seq'::regclass);


--
-- Name: command_templates id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.command_templates ALTER COLUMN id SET DEFAULT nextval('public.command_templates_id_seq'::regclass);


--
-- Name: command_validation_logs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.command_validation_logs ALTER COLUMN id SET DEFAULT nextval('public.command_validation_logs_id_seq'::regclass);


--
-- Name: command_validation_rules id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.command_validation_rules ALTER COLUMN id SET DEFAULT nextval('public.command_validation_rules_id_seq'::regclass);


--
-- Name: command_whitelist id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.command_whitelist ALTER COLUMN id SET DEFAULT nextval('public.command_whitelist_id_seq'::regclass);


--
-- Name: compliance_policies id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.compliance_policies ALTER COLUMN id SET DEFAULT nextval('public.compliance_policies_id_seq'::regclass);


--
-- Name: compliance_policy_checks id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.compliance_policy_checks ALTER COLUMN id SET DEFAULT nextval('public.compliance_policy_checks_id_seq'::regclass);


--
-- Name: compliance_policy_evidence id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.compliance_policy_evidence ALTER COLUMN id SET DEFAULT nextval('public.compliance_policy_evidence_id_seq'::regclass);


--
-- Name: compliance_remediation_execution_attempts id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.compliance_remediation_execution_attempts ALTER COLUMN id SET DEFAULT nextval('public.compliance_remediation_execution_attempts_id_seq'::regclass);


--
-- Name: compliance_remediation_plans id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.compliance_remediation_plans ALTER COLUMN id SET DEFAULT nextval('public.compliance_remediation_plans_id_seq'::regclass);


--
-- Name: compliance_remediation_requests id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.compliance_remediation_requests ALTER COLUMN id SET DEFAULT nextval('public.compliance_remediation_requests_id_seq'::regclass);


--
-- Name: content_channel_repos id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.content_channel_repos ALTER COLUMN id SET DEFAULT nextval('public.content_channel_repos_id_seq'::regclass);


--
-- Name: content_channels id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.content_channels ALTER COLUMN id SET DEFAULT nextval('public.content_channels_id_seq'::regclass);


--
-- Name: content_profile_channels id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.content_profile_channels ALTER COLUMN id SET DEFAULT nextval('public.content_profile_channels_id_seq'::regclass);


--
-- Name: content_profiles id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.content_profiles ALTER COLUMN id SET DEFAULT nextval('public.content_profiles_id_seq'::regclass);


--
-- Name: credentials id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.credentials ALTER COLUMN id SET DEFAULT nextval('public.credentials_id_seq'::regclass);


--
-- Name: distro_lifecycle id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.distro_lifecycle ALTER COLUMN id SET DEFAULT nextval('public.distro_lifecycle_id_seq'::regclass);


--
-- Name: distro_lifecycle_override id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.distro_lifecycle_override ALTER COLUMN id SET DEFAULT nextval('public.distro_lifecycle_override_id_seq'::regclass);


--
-- Name: distros id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.distros ALTER COLUMN id SET DEFAULT nextval('public.distros_id_seq'::regclass);


--
-- Name: file_transfer_audits id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.file_transfer_audits ALTER COLUMN id SET DEFAULT nextval('public.file_transfer_audits_id_seq'::regclass);


--
-- Name: fleet_operation_results id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.fleet_operation_results ALTER COLUMN id SET DEFAULT nextval('public.fleet_operation_results_id_seq'::regclass);


--
-- Name: fleet_operations id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.fleet_operations ALTER COLUMN id SET DEFAULT nextval('public.fleet_operations_id_seq'::regclass);


--
-- Name: fleet_roles id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.fleet_roles ALTER COLUMN id SET DEFAULT nextval('public.fleet_roles_id_seq'::regclass);


--
-- Name: global_connection_settings id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.global_connection_settings ALTER COLUMN id SET DEFAULT nextval('public.global_connection_settings_id_seq'::regclass);


--
-- Name: group_content_profile_subscriptions id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.group_content_profile_subscriptions ALTER COLUMN id SET DEFAULT nextval('public.group_content_profile_subscriptions_id_seq'::regclass);


--
-- Name: groups id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.groups ALTER COLUMN id SET DEFAULT nextval('public.groups_id_seq'::regclass);


--
-- Name: host_content_profile_subscriptions id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.host_content_profile_subscriptions ALTER COLUMN id SET DEFAULT nextval('public.host_content_profile_subscriptions_id_seq'::regclass);


--
-- Name: host_facts id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.host_facts ALTER COLUMN id SET DEFAULT nextval('public.host_facts_id_seq'::regclass);


--
-- Name: host_mirror_serve_credentials id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.host_mirror_serve_credentials ALTER COLUMN id SET DEFAULT nextval('public.host_mirror_serve_credentials_id_seq'::regclass);


--
-- Name: host_mirror_trust id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.host_mirror_trust ALTER COLUMN id SET DEFAULT nextval('public.host_mirror_trust_id_seq'::regclass);


--
-- Name: host_user_states id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.host_user_states ALTER COLUMN id SET DEFAULT nextval('public.host_user_states_id_seq'::regclass);


--
-- Name: job_history id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.job_history ALTER COLUMN id SET DEFAULT nextval('public.job_history_id_seq'::regclass);


--
-- Name: jobs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.jobs ALTER COLUMN id SET DEFAULT nextval('public.jobs_id_seq'::regclass);


--
-- Name: lifecycle_notification_state id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.lifecycle_notification_state ALTER COLUMN id SET DEFAULT nextval('public.lifecycle_notification_state_id_seq'::regclass);


--
-- Name: maintenance_windows id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.maintenance_windows ALTER COLUMN id SET DEFAULT nextval('public.maintenance_windows_id_seq'::regclass);


--
-- Name: mirror_alert_state id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mirror_alert_state ALTER COLUMN id SET DEFAULT nextval('public.mirror_alert_state_id_seq'::regclass);


--
-- Name: mirror_repos id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mirror_repos ALTER COLUMN id SET DEFAULT nextval('public.mirror_repos_id_seq'::regclass);


--
-- Name: mirror_signing_keys id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mirror_signing_keys ALTER COLUMN id SET DEFAULT nextval('public.mirror_signing_keys_id_seq'::regclass);


--
-- Name: mirror_sync_run_packages id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mirror_sync_run_packages ALTER COLUMN id SET DEFAULT nextval('public.mirror_sync_run_packages_id_seq'::regclass);


--
-- Name: mirror_sync_runs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mirror_sync_runs ALTER COLUMN id SET DEFAULT nextval('public.mirror_sync_runs_id_seq'::regclass);


--
-- Name: mirror_upstream_keys id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mirror_upstream_keys ALTER COLUMN id SET DEFAULT nextval('public.mirror_upstream_keys_id_seq'::regclass);


--
-- Name: notification_preferences id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.notification_preferences ALTER COLUMN id SET DEFAULT nextval('public.notification_preferences_id_seq'::regclass);


--
-- Name: notifications id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.notifications ALTER COLUMN id SET DEFAULT nextval('public.notifications_id_seq'::regclass);


--
-- Name: oidc_login_state id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oidc_login_state ALTER COLUMN id SET DEFAULT nextval('public.oidc_login_state_id_seq'::regclass);


--
-- Name: oidc_provider id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oidc_provider ALTER COLUMN id SET DEFAULT nextval('public.oidc_provider_id_seq'::regclass);


--
-- Name: package_history id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.package_history ALTER COLUMN id SET DEFAULT nextval('public.package_history_id_seq'::regclass);


--
-- Name: package_updates id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.package_updates ALTER COLUMN id SET DEFAULT nextval('public.package_updates_id_seq'::regclass);


--
-- Name: packages id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.packages ALTER COLUMN id SET DEFAULT nextval('public.packages_id_seq'::regclass);


--
-- Name: patch_advisories id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_advisories ALTER COLUMN id SET DEFAULT nextval('public.patch_advisories_id_seq'::regclass);


--
-- Name: patch_advisory_fixed_packages id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_advisory_fixed_packages ALTER COLUMN id SET DEFAULT nextval('public.patch_advisory_fixed_packages_id_seq'::regclass);


--
-- Name: patch_advisory_host_applicability id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_advisory_host_applicability ALTER COLUMN id SET DEFAULT nextval('public.patch_advisory_host_applicability_id_seq'::regclass);


--
-- Name: patch_advisory_imports id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_advisory_imports ALTER COLUMN id SET DEFAULT nextval('public.patch_advisory_imports_id_seq'::regclass);


--
-- Name: patch_approval_votes id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_approval_votes ALTER COLUMN id SET DEFAULT nextval('public.patch_approval_votes_id_seq'::regclass);


--
-- Name: patch_approvals id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_approvals ALTER COLUMN id SET DEFAULT nextval('public.patch_approvals_id_seq'::regclass);


--
-- Name: patch_policies id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_policies ALTER COLUMN id SET DEFAULT nextval('public.patch_policies_id_seq'::regclass);


--
-- Name: patch_policy_group_bindings id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_policy_group_bindings ALTER COLUMN id SET DEFAULT nextval('public.patch_policy_group_bindings_id_seq'::regclass);


--
-- Name: patch_policy_host_bindings id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_policy_host_bindings ALTER COLUMN id SET DEFAULT nextval('public.patch_policy_host_bindings_id_seq'::regclass);


--
-- Name: patch_policy_ring_bindings id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_policy_ring_bindings ALTER COLUMN id SET DEFAULT nextval('public.patch_policy_ring_bindings_id_seq'::regclass);


--
-- Name: patch_policy_smart_group_bindings id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_policy_smart_group_bindings ALTER COLUMN id SET DEFAULT nextval('public.patch_policy_smart_group_bindings_id_seq'::regclass);


--
-- Name: patch_ring_gate_definitions id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_ring_gate_definitions ALTER COLUMN id SET DEFAULT nextval('public.patch_ring_gate_definitions_id_seq'::regclass);


--
-- Name: patch_ring_gate_signals id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_ring_gate_signals ALTER COLUMN id SET DEFAULT nextval('public.patch_ring_gate_signals_id_seq'::regclass);


--
-- Name: patch_ring_group_bindings id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_ring_group_bindings ALTER COLUMN id SET DEFAULT nextval('public.patch_ring_group_bindings_id_seq'::regclass);


--
-- Name: patch_ring_host_bindings id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_ring_host_bindings ALTER COLUMN id SET DEFAULT nextval('public.patch_ring_host_bindings_id_seq'::regclass);


--
-- Name: patch_ring_smart_group_bindings id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_ring_smart_group_bindings ALTER COLUMN id SET DEFAULT nextval('public.patch_ring_smart_group_bindings_id_seq'::regclass);


--
-- Name: patch_rings id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_rings ALTER COLUMN id SET DEFAULT nextval('public.patch_rings_id_seq'::regclass);


--
-- Name: patch_rollback_dispatch_host_packages id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_rollback_dispatch_host_packages ALTER COLUMN id SET DEFAULT nextval('public.patch_rollback_dispatch_host_packages_id_seq'::regclass);


--
-- Name: patch_rollback_dispatch_hosts id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_rollback_dispatch_hosts ALTER COLUMN id SET DEFAULT nextval('public.patch_rollback_dispatch_hosts_id_seq'::regclass);


--
-- Name: patch_rollback_dispatch_runs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_rollback_dispatch_runs ALTER COLUMN id SET DEFAULT nextval('public.patch_rollback_dispatch_runs_id_seq'::regclass);


--
-- Name: patch_update_execution_host_packages id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_update_execution_host_packages ALTER COLUMN id SET DEFAULT nextval('public.patch_update_execution_host_packages_id_seq'::regclass);


--
-- Name: patch_update_execution_hosts id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_update_execution_hosts ALTER COLUMN id SET DEFAULT nextval('public.patch_update_execution_hosts_id_seq'::regclass);


--
-- Name: patch_update_execution_reboots id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_update_execution_reboots ALTER COLUMN id SET DEFAULT nextval('public.patch_update_execution_reboots_id_seq'::regclass);


--
-- Name: patch_update_execution_rollback_approvals id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_update_execution_rollback_approvals ALTER COLUMN id SET DEFAULT nextval('public.patch_update_execution_rollback_approvals_id_seq'::regclass);


--
-- Name: patch_update_execution_rollback_hosts id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_update_execution_rollback_hosts ALTER COLUMN id SET DEFAULT nextval('public.patch_update_execution_rollback_hosts_id_seq'::regclass);


--
-- Name: patch_update_execution_rollback_packages id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_update_execution_rollback_packages ALTER COLUMN id SET DEFAULT nextval('public.patch_update_execution_rollback_packages_id_seq'::regclass);


--
-- Name: patch_update_execution_rollbacks id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_update_execution_rollbacks ALTER COLUMN id SET DEFAULT nextval('public.patch_update_execution_rollbacks_id_seq'::regclass);


--
-- Name: patch_update_executions id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_update_executions ALTER COLUMN id SET DEFAULT nextval('public.patch_update_executions_id_seq'::regclass);


--
-- Name: patch_update_plan_approvals id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_update_plan_approvals ALTER COLUMN id SET DEFAULT nextval('public.patch_update_plan_approvals_id_seq'::regclass);


--
-- Name: patch_update_plan_hosts id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_update_plan_hosts ALTER COLUMN id SET DEFAULT nextval('public.patch_update_plan_hosts_id_seq'::regclass);


--
-- Name: patch_update_plan_preflight_snapshots id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_update_plan_preflight_snapshots ALTER COLUMN id SET DEFAULT nextval('public.patch_update_plan_preflight_snapshots_id_seq'::regclass);


--
-- Name: patch_update_plan_selected_packages id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_update_plan_selected_packages ALTER COLUMN id SET DEFAULT nextval('public.patch_update_plan_selected_packages_id_seq'::regclass);


--
-- Name: patch_update_plans id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_update_plans ALTER COLUMN id SET DEFAULT nextval('public.patch_update_plans_id_seq'::regclass);


--
-- Name: recordings id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.recordings ALTER COLUMN id SET DEFAULT nextval('public.recordings_id_seq'::regclass);


--
-- Name: refresh_tokens id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.refresh_tokens ALTER COLUMN id SET DEFAULT nextval('public.refresh_tokens_id_seq'::regclass);


--
-- Name: repo_sources id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.repo_sources ALTER COLUMN id SET DEFAULT nextval('public.repo_sources_id_seq'::regclass);


--
-- Name: report_runs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.report_runs ALTER COLUMN id SET DEFAULT nextval('public.report_runs_id_seq'::regclass);


--
-- Name: report_schedules id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.report_schedules ALTER COLUMN id SET DEFAULT nextval('public.report_schedules_id_seq'::regclass);


--
-- Name: revocation_work id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.revocation_work ALTER COLUMN id SET DEFAULT nextval('public.revocation_work_id_seq'::regclass);


--
-- Name: role id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role ALTER COLUMN id SET DEFAULT nextval('public.role_id_seq'::regclass);


--
-- Name: saved_views id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.saved_views ALTER COLUMN id SET DEFAULT nextval('public.saved_views_id_seq'::regclass);


--
-- Name: scheduler_job_locks id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scheduler_job_locks ALTER COLUMN id SET DEFAULT nextval('public.scheduler_job_locks_id_seq'::regclass);


--
-- Name: session_approvals id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.session_approvals ALTER COLUMN id SET DEFAULT nextval('public.session_approvals_id_seq'::regclass);


--
-- Name: session_locks id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.session_locks ALTER COLUMN id SET DEFAULT nextval('public.session_locks_id_seq'::regclass);


--
-- Name: sessions id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sessions ALTER COLUMN id SET DEFAULT nextval('public.sessions_id_seq'::regclass);


--
-- Name: smart_group_content_profile_subscriptions id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.smart_group_content_profile_subscriptions ALTER COLUMN id SET DEFAULT nextval('public.smart_group_content_profile_subscriptions_id_seq'::regclass);


--
-- Name: smart_group_memberships id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.smart_group_memberships ALTER COLUMN id SET DEFAULT nextval('public.smart_group_memberships_id_seq'::regclass);


--
-- Name: smart_groups id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.smart_groups ALTER COLUMN id SET DEFAULT nextval('public.smart_groups_id_seq'::regclass);


--
-- Name: ssh_host_keys id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ssh_host_keys ALTER COLUMN id SET DEFAULT nextval('public.ssh_host_keys_id_seq'::regclass);


--
-- Name: ssh_identity_settings id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ssh_identity_settings ALTER COLUMN id SET DEFAULT nextval('public.ssh_identity_settings_id_seq'::regclass);


--
-- Name: ssh_security_logs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ssh_security_logs ALTER COLUMN id SET DEFAULT nextval('public.ssh_security_logs_id_seq'::regclass);


--
-- Name: ssh_security_policies id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ssh_security_policies ALTER COLUMN id SET DEFAULT nextval('public.ssh_security_policies_id_seq'::regclass);


--
-- Name: system_audits id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.system_audits ALTER COLUMN id SET DEFAULT nextval('public.system_audits_id_seq'::regclass);


--
-- Name: system_metadata id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.system_metadata ALTER COLUMN id SET DEFAULT nextval('public.system_metadata_id_seq'::regclass);


--
-- Name: systems id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.systems ALTER COLUMN id SET DEFAULT nextval('public.systems_id_seq'::regclass);


--
-- Name: tags id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tags ALTER COLUMN id SET DEFAULT nextval('public.tags_id_seq'::regclass);


--
-- Name: totp_challenges id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.totp_challenges ALTER COLUMN id SET DEFAULT nextval('public.totp_challenges_id_seq'::regclass);


--
-- Name: user id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public."user" ALTER COLUMN id SET DEFAULT nextval('public.user_id_seq'::regclass);


--
-- Name: vault_config id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vault_config ALTER COLUMN id SET DEFAULT nextval('public.vault_config_id_seq'::regclass);


--
-- Data for Name: access_bindings; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.access_bindings (id, subject_user_id, subject_app_role_id, scope_group_id, scope_smart_group_id, fleet_role_id, enabled, expires_at, created_by, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: access_grants; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.access_grants (id, user_id, system_id, fleet_role_id, login, via_binding_id, is_implicit_admin, created_at, updated_at, expires_at) FROM stdin;
\.


--
-- Data for Name: access_requests; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.access_requests (id, requested_by, fleet_role_id, scope_group_id, scope_smart_group_id, justification, duration_seconds, status, decided_by, decided_at, decision_comment, resulting_binding_id, requested_at, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: access_review_items; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.access_review_items (id, review_id, binding_id, binding_snapshot_json, action, decided_at, decided_by, notes, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: access_reviews; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.access_reviews (id, scope, scope_ref_id, state, due_at, completed_at, reviewer_id, summary, created_by, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: activation_token_redemptions; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.activation_token_redemptions (id, activation_token_id, host_fingerprint_hash, system_id, first_redeemed_at, last_redeemed_at, redeem_count, last_seen_hostname, last_seen_ip, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: activation_tokens; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.activation_tokens (id, name, token_hash, token_prefix, default_group_id, default_tag_ids, ttl_expires_at, max_uses, uses_count, revoked_at, revoked_by_user_id, created_by_user_id, created_at, updated_at, target_system_id) FROM stdin;
\.


--
-- Data for Name: airgap_bundle_signing_keys; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.airgap_bundle_signing_keys (id, status, gpg_fingerprint, key_uid, vault_path, armored_public_key, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: airgap_bundles; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.airgap_bundles (id, bundle_id, kind, parent_bundle_id, status, bundle_descriptor_path, bundle_path, payload_sha256, byte_count, signing_key_id, request_payload, error_text, started_at, finished_at, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: airgap_import_trust_keys; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.airgap_import_trust_keys (id, gpg_fingerprint, key_uid, armored_public_key, added_at, deleted_at, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: airgap_imports; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.airgap_imports (id, bundle_id, parent_bundle_id, kind, status, payload_sha256, byte_count, error_text, started_at, finished_at, created_at, updated_at, path, target_mirror_slugs) FROM stdin;
\.


--
-- Data for Name: alembic_version; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.alembic_version (version_num) FROM stdin;
align_groups_id_sequence
\.


--
-- Data for Name: alert_configs; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.alert_configs (id, name, alert_type, destination, events, enabled, created_by, created_at, updated_at, secret, scope_smart_group_id) FROM stdin;
\.


--
-- Data for Name: alert_history; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.alert_history (id, alert_config_id, event_type, message, sent_at, status, error_message, response_code, created_at, updated_at, payload, attempt_count, next_retry_at, last_attempted_at) FROM stdin;
\.


--
-- Data for Name: app_settings; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.app_settings (id, setting_key, setting_value, created_at, updated_at) FROM stdin;
1	app_name	Praxis	2026-08-30 16:39:44.642627	2026-08-30 16:39:44.642627
2	timezone	UTC	2026-08-30 16:39:44.642627	2026-08-30 16:39:44.642627
3	date_format	YYYY-MM-DD	2026-08-30 16:39:44.642627	2026-08-30 16:39:44.642627
4	time_format	24h	2026-08-30 16:39:44.642627	2026-08-30 16:39:44.642627
\.


--
-- Data for Name: audit_events; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.audit_events (id, schema_version, event_uuid, "timestamp", action, outcome, actor_user_id, actor_username, actor_ip, target_system_id, target_kind, target_id, context_json, created_at, updated_at) FROM stdin;
1	1	00000000-0000-4000-8000-000000000001	2026-01-15 12:00:00	patch_update_plan.created	success	\N	\N	\N	\N	patch_update_plan	1	{}	2026-01-15 12:00:00	2026-01-15 12:00:00
2	1	00000000-0000-4000-8000-000000000002	2026-01-15 12:00:00	patch_update_execution.completed	success	\N	\N	\N	\N	patch_update_execution	1	{}	2026-01-15 12:00:00	2026-01-15 12:00:00
3	1	00000000-0000-4000-8000-000000000003	2026-01-15 12:00:00	host_facts.collected	success	\N	\N	\N	3	system	3	{}	2026-01-15 12:00:00	2026-01-15 12:00:00
4	1	00000000-0000-4000-8000-000000000004	2026-01-15 12:00:00	audit_sink.created	success	\N	\N	\N	\N	audit_sink	1	{}	2026-01-15 12:00:00	2026-01-15 12:00:00
\.


--
-- Data for Name: audit_sink_deliveries; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.audit_sink_deliveries (id, sink_id, event_id, status, attempts, last_error, next_attempt_at, delivered_at, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: audit_sinks; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.audit_sinks (id, name, kind, target, hmac_secret, config_json, enabled, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: baseline_checks; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.baseline_checks (id, baseline_id, system_id, run_at, status, drift_details_json, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: baselines; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.baselines (id, name, description, scope_smart_group_id, rules_json, enabled, schedule_interval_hours, last_run_at, created_by, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: ca_rotations; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.ca_rotations (id, event_type, ca_identifier, ca_public_key, performed_by, performed_at, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: command_approval_votes; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.command_approval_votes (id, approval_id, user_id, decision, comment, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: command_approvals; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.command_approvals (id, command, system_id, whitelist_entry_id, requested_by, decided_by, status, comment, timeout_seconds, session_id, requested_at, decided_at, created_at, updated_at, expires_at, required_approvals) FROM stdin;
\.


--
-- Data for Name: command_distro_mapping; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.command_distro_mapping (id, command_id, distro_id, distro_version_pattern, command_override, is_supported, notes, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: command_execution_metrics; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.command_execution_metrics (id, system_id, user_id, metric_date, metric_hour, total_executions, successful_executions, failed_executions, timeout_executions, avg_execution_time_ms, max_execution_time_ms, min_execution_time_ms, avg_memory_usage_bytes, max_memory_usage_bytes, total_cpu_time_ms, validation_failures, high_risk_executions, sudo_executions, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: command_execution_policies; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.command_execution_policies (id, name, description, default_timeout_seconds, max_timeout_seconds, max_memory_bytes, max_cpu_time_ms, max_disk_io_bytes, max_network_io_bytes, max_open_files, max_processes, allow_sudo, allow_network_access, allow_file_system_write, require_validation, max_retry_attempts, retry_delay_seconds, log_stdout, log_stderr, monitor_resources, applies_to_all_systems, applies_to_all_users, is_active, priority, created_at, updated_at, created_by) FROM stdin;
\.


--
-- Data for Name: command_execution_queue; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.command_execution_queue (id, system_id, user_id, command, priority, status, scheduled_at, started_at, completed_at, timeout_seconds, retry_count, max_retries, execution_result_id, error_message, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: command_execution_results; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.command_execution_results (id, system_id, user_id, session_id, command, normalized_command, command_hash, execution_status, exit_code, stdout, stderr, started_at, completed_at, execution_time_ms, timeout_seconds, max_memory_usage_bytes, cpu_time_ms, disk_io_bytes, network_io_bytes, validation_status, risk_level, requires_sudo, actual_user, ip_address, user_agent, execution_context, error_type, error_message, retry_count, created_at, updated_at, transport) FROM stdin;
\.


--
-- Data for Name: command_execution_system_policies; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.command_execution_system_policies (id, policy_id, system_id, timeout_override, memory_limit_override, is_active, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: command_execution_user_policies; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.command_execution_user_policies (id, policy_id, user_id, timeout_override, memory_limit_override, is_active, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: command_resource_limits; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.command_resource_limits (id, execution_result_id, max_memory_bytes, max_cpu_time_ms, max_disk_io_bytes, max_network_io_bytes, max_open_files, max_processes, memory_limit_exceeded, cpu_limit_exceeded, disk_io_limit_exceeded, network_io_limit_exceeded, limit_source, policy_name, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: command_template_distros; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.command_template_distros (id, template_id, distro_id, distro_version_pattern, template_override, is_supported, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: command_templates; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.command_templates (id, name, description, template, category, parameters, is_active, risk_level, requires_approval, created_at, updated_at, created_by) FROM stdin;
\.


--
-- Data for Name: command_validation_logs; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.command_validation_logs (id, command_id, validation_rule_id, system_id, raw_command, normalized_command, validation_status, validation_reason, user_id, session_id, ip_address, user_agent, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: command_validation_rules; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.command_validation_rules (id, name, description, validation_type, pattern, is_regex, is_active, severity, error_message, created_at, updated_at, created_by) FROM stdin;
1	Dangerous File Operations	Block recursive removal of /	blacklist	rm\\s+-rf\\s+/	t	t	critical	\N	2026-01-15 12:00:00	2026-01-15 12:00:00	1
\.


--
-- Data for Name: command_whitelist; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.command_whitelist (id, name, description, command_pattern, is_regex, is_active, risk_level, category, requires_sudo, timeout_seconds, created_at, updated_at, created_by, requires_approval, required_approvals) FROM stdin;
1	APT Update	Update package lists	apt-get update	f	t	low	package_management	t	300	2026-01-15 12:00:00	2026-01-15 12:00:00	1	f	1
2	APT Upgrade	Upgrade installed packages	apt-get upgrade	f	t	medium	package_management	t	600	2026-01-15 12:00:00	2026-01-15 12:00:00	1	f	1
\.


--
-- Data for Name: compliance_policies; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.compliance_policies (id, slug, name, description, severity, category, schedule_interval_hours, evidence_retention_days, remediation_guidance, enabled, version, built_in, starter_pack_key, created_by, created_at, updated_at, last_run_at, last_run_status) FROM stdin;
\.


--
-- Data for Name: compliance_policy_checks; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.compliance_policy_checks (id, policy_id, slug, title, description, kind, definition_json, severity_override, remediation_guidance, enabled, display_order, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: compliance_policy_evidence; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.compliance_policy_evidence (id, policy_id, check_id, system_id, policy_slug, policy_version, check_slug, check_kind, verdict, verdict_reason, observed_value, expected_value, severity, evaluation_run_id, evaluated_at, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: compliance_remediation_execution_attempts; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.compliance_remediation_execution_attempts (id, request_id, plan_id, policy_id, check_id, system_id, policy_slug, policy_version, check_slug, check_kind, severity_snapshot, plan_kind_snapshot, package_name, package_version_target, approval_decided_by, approval_decided_at, state, transport, failure_reason, error_message, dispatched_at, completed_at, created_by, created_at, updated_at, exit_code, duration_ms, stdout_summary, stderr_summary, dispatch_details) FROM stdin;
\.


--
-- Data for Name: compliance_remediation_plans; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.compliance_remediation_plans (id, request_id, policy_id, check_id, system_id, policy_slug, policy_version, check_slug, check_kind, severity_snapshot, state, plan_kind, plan_steps, unsupported_reason, error_message, created_by, created_at, updated_at, check_definition_fingerprint, acknowledged_at, acknowledged_by, superseded_by_plan_id) FROM stdin;
\.


--
-- Data for Name: compliance_remediation_requests; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.compliance_remediation_requests (id, policy_id, check_id, system_id, evidence_id, policy_slug, policy_version, check_slug, check_kind, evaluation_run_id, verdict_snapshot, verdict_reason_snapshot, severity_snapshot, remediation_guidance_snapshot, state, justification, requested_by, decided_by, decided_at, decided_reason, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: content_channel_repos; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.content_channel_repos (id, channel_id, mirror_id, suite_override, pinned_run_id, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: content_channels; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.content_channels (id, slug, display_name, package_family, description, deleted_at, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: content_profile_channels; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.content_profile_channels (id, profile_id, channel_id, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: content_profiles; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.content_profiles (id, slug, display_name, package_family, description, deleted_at, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: credentials; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.credentials (id, name, auth_method, username, created_at, updated_at, sudo_method, vault_path) FROM stdin;
1	fixture-key	ssh_key	\N	2026-01-15 12:00:00	2026-01-15 12:00:00	none	\N
\.


--
-- Data for Name: distro_lifecycle; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.distro_lifecycle (id, distro_id, release, eol_date, support_kind, source, as_of, created_at, updated_at) FROM stdin;
1	ubuntu	14.04	2019-04-25	standard	endoflife.date	2026-05-02	2026-08-30 16:39:44.642627	2026-08-30 16:39:44.642627
2	ubuntu	14.04	2024-04-30	esm	endoflife.date	2026-05-02	2026-08-30 16:39:44.642627	2026-08-30 16:39:44.642627
3	ubuntu	16.04	2021-04-30	standard	endoflife.date	2026-05-02	2026-08-30 16:39:44.642627	2026-08-30 16:39:44.642627
4	ubuntu	16.04	2026-04-30	esm	endoflife.date	2026-05-02	2026-08-30 16:39:44.642627	2026-08-30 16:39:44.642627
5	ubuntu	18.04	2023-05-31	standard	endoflife.date	2026-05-02	2026-08-30 16:39:44.642627	2026-08-30 16:39:44.642627
6	ubuntu	18.04	2028-05-31	esm	endoflife.date	2026-05-02	2026-08-30 16:39:44.642627	2026-08-30 16:39:44.642627
7	ubuntu	20.04	2025-04-29	standard	endoflife.date	2026-05-02	2026-08-30 16:39:44.642627	2026-08-30 16:39:44.642627
8	ubuntu	20.04	2030-04-29	esm	endoflife.date	2026-05-02	2026-08-30 16:39:44.642627	2026-08-30 16:39:44.642627
9	ubuntu	22.04	2027-06-01	standard	endoflife.date	2026-05-02	2026-08-30 16:39:44.642627	2026-08-30 16:39:44.642627
10	ubuntu	22.04	2032-06-01	esm	endoflife.date	2026-05-02	2026-08-30 16:39:44.642627	2026-08-30 16:39:44.642627
11	ubuntu	24.04	2029-06-01	standard	endoflife.date	2026-05-02	2026-08-30 16:39:44.642627	2026-08-30 16:39:44.642627
12	ubuntu	24.04	2034-06-01	esm	endoflife.date	2026-05-02	2026-08-30 16:39:44.642627	2026-08-30 16:39:44.642627
13	ubuntu	26.04	2031-06-01	standard	endoflife.date	2026-07-16	2026-08-30 16:39:44.642627	2026-08-30 16:39:44.642627
14	ubuntu	26.04	2036-06-01	esm	endoflife.date	2026-07-16	2026-08-30 16:39:44.642627	2026-08-30 16:39:44.642627
15	rhel	7	2024-06-30	standard	endoflife.date	2026-05-02	2026-08-30 16:39:44.642627	2026-08-30 16:39:44.642627
16	rhel	7	2028-06-30	extended	endoflife.date	2026-05-02	2026-08-30 16:39:44.642627	2026-08-30 16:39:44.642627
17	rhel	8	2029-05-31	standard	endoflife.date	2026-05-02	2026-08-30 16:39:44.642627	2026-08-30 16:39:44.642627
18	rhel	9	2032-05-31	standard	endoflife.date	2026-05-02	2026-08-30 16:39:44.642627	2026-08-30 16:39:44.642627
19	rhel	10	2035-05-31	standard	endoflife.date	2026-07-16	2026-08-30 16:39:44.642627	2026-08-30 16:39:44.642627
20	rocky	8	2029-05-31	standard	endoflife.date	2026-05-02	2026-08-30 16:39:44.642627	2026-08-30 16:39:44.642627
21	rocky	9	2032-05-31	standard	endoflife.date	2026-05-02	2026-08-30 16:39:44.642627	2026-08-30 16:39:44.642627
22	rocky	10	2035-05-31	standard	endoflife.date	2026-07-16	2026-08-30 16:39:44.642627	2026-08-30 16:39:44.642627
23	almalinux	8	2029-03-01	standard	endoflife.date	2026-05-02	2026-08-30 16:39:44.642627	2026-08-30 16:39:44.642627
24	almalinux	9	2032-05-31	standard	endoflife.date	2026-05-02	2026-08-30 16:39:44.642627	2026-08-30 16:39:44.642627
25	almalinux	10	2035-05-31	standard	endoflife.date	2026-07-16	2026-08-30 16:39:44.642627	2026-08-30 16:39:44.642627
26	debian	10	2022-09-10	standard	endoflife.date	2026-05-02	2026-08-30 16:39:44.642627	2026-08-30 16:39:44.642627
27	debian	10	2024-06-30	extended	endoflife.date	2026-05-02	2026-08-30 16:39:44.642627	2026-08-30 16:39:44.642627
28	debian	11	2024-08-14	standard	endoflife.date	2026-05-02	2026-08-30 16:39:44.642627	2026-08-30 16:39:44.642627
29	debian	11	2026-08-31	extended	endoflife.date	2026-05-02	2026-08-30 16:39:44.642627	2026-08-30 16:39:44.642627
30	debian	12	2026-06-10	standard	endoflife.date	2026-05-02	2026-08-30 16:39:44.642627	2026-08-30 16:39:44.642627
31	debian	12	2028-06-30	extended	endoflife.date	2026-05-02	2026-08-30 16:39:44.642627	2026-08-30 16:39:44.642627
32	debian	13	2028-08-09	standard	endoflife.date	2026-07-16	2026-08-30 16:39:44.642627	2026-08-30 16:39:44.642627
33	debian	13	2030-06-30	extended	endoflife.date	2026-07-16	2026-08-30 16:39:44.642627	2026-08-30 16:39:44.642627
\.


--
-- Data for Name: distro_lifecycle_override; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.distro_lifecycle_override (id, scope_type, scope_id, distro_id, release, eol_date, support_kind, source, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: distros; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.distros (id, name, version, release_date, end_of_life_date, created_at, updated_at) FROM stdin;
1	Ubuntu	24.04	2024-04-25	2034-04-25	2026-01-15 12:00:00	2026-01-15 12:00:00
\.


--
-- Data for Name: file_transfer_audits; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.file_transfer_audits (id, user_id, system_id, login, direction, remote_path, local_filename, size_bytes, sha256, status, error_message, client_ip, started_at, ended_at, created_at, updated_at, transport) FROM stdin;
\.


--
-- Data for Name: fleet_operation_results; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.fleet_operation_results (id, fleet_operation_id, system_id, status, error_message, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: fleet_operations; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.fleet_operations (id, operation_type, user_id, target_count, success_count, failure_count, parameters, status, created_at, completed_at, updated_at) FROM stdin;
\.


--
-- Data for Name: fleet_roles; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.fleet_roles (id, name, description, login_mode, role_account_name, allowed_actions_json, session_requires_approval, totp_required, idle_timeout_s, max_session_s, os_groups_json, sudoers_snippet, is_builtin, created_at, updated_at, recording_retention_days) FROM stdin;
3	auditor	Read-only access. Interactive shell only. No command execution API, no file transfer, no sudo.	per_user	\N	["session_open"]	f	f	900	3600	[]	\N	t	2026-08-30 16:39:44.642627	2026-08-30 16:39:44.642627	90
1	admin	Full administrative access. Interactive shell, command execution, file transfer, passwordless sudo. Added to wheel / sudo group (whichever exists on the host).	per_user	\N	["session_open", "command_exec", "file_transfer"]	f	f	900	3600	[]	\N	t	2026-08-30 16:39:44.642627	2026-08-30 16:39:44.642627	90
2	maintainer	Fleet operator. Interactive shell, command execution, file transfer, passwordless sudo.	per_user	\N	["session_open", "command_exec", "file_transfer"]	f	f	900	3600	[]	\N	t	2026-08-30 16:39:44.642627	2026-08-30 16:39:44.642627	90
\.


--
-- Data for Name: global_connection_settings; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.global_connection_settings (id, connection_timeout, max_pool_size, pool_cleanup_interval, max_idle_time, unreachable_threshold, default_ssh_port, created_at, updated_at, transport_failure_threshold, transport_cooldown_seconds) FROM stdin;
1	10	50	300	600	2	22	2026-08-30 16:39:44.642627	2026-08-30 16:39:44.642627	3	60
\.


--
-- Data for Name: group_content_profile_subscriptions; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.group_content_profile_subscriptions (id, group_id, profile_id, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: groups; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.groups (id, name, description, parent_id, created_at, updated_at) FROM stdin;
1	All Systems	Default group containing all systems	\N	2026-01-15 12:00:00	2026-01-15 12:00:00
\.


--
-- Data for Name: host_content_profile_subscriptions; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.host_content_profile_subscriptions (id, host_id, profile_id, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: host_facts; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.host_facts (id, system_id, schema_version, collected_at, source_transport, cpu_model, cpu_cores, ram_total_bytes, kernel_version, distro_id_facts, distro_release, uptime_seconds, reboot_required, package_manager, package_manager_version, virtualization, cloud_provider, cloud_instance_metadata, disks, partial_errors, created_at, updated_at, ssh_permit_root_login, ssh_password_authentication, sysctl_kernel_randomize_va_space, sysctl_net_ipv4_ip_forward, sysctl_net_ipv4_conf_all_rp_filter) FROM stdin;
\.


--
-- Data for Name: host_mirror_serve_credentials; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.host_mirror_serve_credentials (id, host_id, mirror_id, token_hash, issued_at, expires_at, last_used_at, revoked_at, created_at, updated_at, token_id) FROM stdin;
\.


--
-- Data for Name: host_mirror_trust; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.host_mirror_trust (id, host_id, mirror_id, installed_fingerprints, last_installed_at, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: host_user_states; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.host_user_states (id, system_id, login, mode, state, last_error, last_reconciled_at, home_archive_path, created_at, updated_at, privilege_reconcile_pending) FROM stdin;
\.


--
-- Data for Name: job_history; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.job_history (id, job_id, start_time, end_time, status, result, error_message, created_at, updated_at, systems_targeted, systems_completed, systems_failed) FROM stdin;
\.


--
-- Data for Name: jobs; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.jobs (id, job_type, schedule, status, last_run, next_run, created_at, created_by, updated_at, name, description, is_recurring, target_type, target_ids, package_filter, tag_match_logic, max_parallel, depends_on_job_id, chain_condition) FROM stdin;
\.


--
-- Data for Name: lifecycle_notification_state; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.lifecycle_notification_state (id, system_id, event_type, threshold_days, effective_eol_date, notified_at, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: maintenance_windows; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.maintenance_windows (id, name, target_type, target_id, schedule, enabled, created_by, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: mirror_alert_state; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.mirror_alert_state (id, mirror_repo_id, event_type, last_fired_at, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: mirror_repos; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.mirror_repos (id, slug, display_name, package_family, upstream_url, distribution, components, architectures, sync_schedule_cron, enabled, source_mode, verify_upstream_signature, retention_keep_count, retention_keep_within_days, disk_budget_bytes, last_sync_started_at, last_sync_finished_at, last_sync_status, last_sync_error, current_disk_bytes, deleted_at, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: mirror_signing_keys; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.mirror_signing_keys (id, mirror_repo_id, status, gpg_fingerprint, key_uid, vault_path, cutover_at, retired_at, created_at, updated_at, armored_public_key) FROM stdin;
\.


--
-- Data for Name: mirror_sync_run_packages; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.mirror_sync_run_packages (id, mirror_sync_run_id, mirror_repo_id, package_name, version, arch, filename, sha256, size, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: mirror_sync_runs; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.mirror_sync_runs (id, mirror_repo_id, started_at, finished_at, status, byte_count, package_count, manifest_sha256, manifest_path, error_text, estimate_unavailable, created_at, updated_at, run_kind, manifest_signature_path, signed_with_key_id) FROM stdin;
\.


--
-- Data for Name: mirror_upstream_keys; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.mirror_upstream_keys (id, name, gpg_fingerprint, armored_public_key, notes, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: notification_preferences; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.notification_preferences (id, user_id, disabled_types, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: notifications; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.notifications (id, type, title, message, severity, is_read, user_id, related_job_id, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: oidc_login_state; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.oidc_login_state (id, state, nonce, provider_id, redirect_uri, expires_at, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: oidc_provider; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.oidc_provider (id, name, discovery_url, client_id, client_secret, role_claim, role_mapping, enabled, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: package_history; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.package_history (id, package_id, system_id, operation, old_version, new_version, performed_at, performed_by, job_history_id, created_at, updated_at, status, error_message) FROM stdin;
\.


--
-- Data for Name: package_updates; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.package_updates (id, package_id, system_id, available_version, update_type, discovered_on, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: packages; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.packages (id, system_id, name, installed_version, installation_date, package_type, is_security_critical, last_audited, created_at, updated_at, is_held) FROM stdin;
\.


--
-- Data for Name: patch_advisories; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.patch_advisories (id, source_kind, source_advisory_id, advisory_class, severity, title, summary, distro_family, published_at, source_updated_at, cve_ids, external_refs, raw, digest, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: patch_advisory_fixed_packages; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.patch_advisory_fixed_packages (id, advisory_id, distro_id, distro_release, package_name, fixed_version, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: patch_advisory_host_applicability; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.patch_advisory_host_applicability (id, system_id, advisory_id, fixed_package_id, package_name, installed_version, required_version, state, reason, evaluated_at, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: patch_advisory_imports; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.patch_advisory_imports (id, source_kind, status, started_at, finished_at, imported_count, refreshed_count, unchanged_count, error_count, error_details, created_by, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: patch_approval_votes; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.patch_approval_votes (id, approval_id, user_id, decision, comment, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: patch_approvals; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.patch_approvals (id, subject_kind, subject_id, status, required_approvals, expires_at, requested_by, decided_by, decided_at, comment, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: patch_policies; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.patch_policies (id, slug, name, description, scope_kind, scope_packages, reboot_policy, reboot_window_id, maintenance_window_id, requires_approval, required_approvals, rollout_cadence, failure_policy, enabled, created_by, created_at, updated_at, is_fleet_default) FROM stdin;
\.


--
-- Data for Name: patch_policy_group_bindings; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.patch_policy_group_bindings (id, policy_id, created_by, created_at, updated_at, group_id) FROM stdin;
\.


--
-- Data for Name: patch_policy_host_bindings; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.patch_policy_host_bindings (id, policy_id, created_by, created_at, updated_at, system_id) FROM stdin;
\.


--
-- Data for Name: patch_policy_ring_bindings; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.patch_policy_ring_bindings (id, policy_id, ring_id, created_by, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: patch_policy_smart_group_bindings; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.patch_policy_smart_group_bindings (id, policy_id, created_by, created_at, updated_at, smart_group_id) FROM stdin;
\.


--
-- Data for Name: patch_ring_gate_definitions; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.patch_ring_gate_definitions (id, ring_id, signal_key, name, description, gate_kind, comparator, parameters, required, enabled, created_by, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: patch_ring_gate_signals; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.patch_ring_gate_signals (id, ring_id, gate_definition_id, signal_key, status, value, details, source_kind, source_ref_kind, source_ref_id, observed_at, expires_at, created_by, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: patch_ring_group_bindings; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.patch_ring_group_bindings (id, ring_id, created_by, created_at, updated_at, group_id) FROM stdin;
\.


--
-- Data for Name: patch_ring_host_bindings; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.patch_ring_host_bindings (id, ring_id, created_by, created_at, updated_at, system_id) FROM stdin;
\.


--
-- Data for Name: patch_ring_smart_group_bindings; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.patch_ring_smart_group_bindings (id, ring_id, created_by, created_at, updated_at, smart_group_id) FROM stdin;
\.


--
-- Data for Name: patch_rings; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.patch_rings (id, slug, name, description, sort_order, enabled, created_by, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: patch_rollback_dispatch_host_packages; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.patch_rollback_dispatch_host_packages (id, rollback_dispatch_host_id, rollback_package_id, package_name, package_manager_family_snapshot, target_rollback_version_snapshot, installed_version_before, installed_version_after, outcome, error_code, details, created_at, updated_at, verified_at) FROM stdin;
\.


--
-- Data for Name: patch_rollback_dispatch_hosts; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.patch_rollback_dispatch_hosts (id, rollback_dispatch_run_id, rollback_host_id, system_id_snapshot, system_hostname_snapshot, state, error_details, started_at, completed_at, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: patch_rollback_dispatch_runs; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.patch_rollback_dispatch_runs (id, rollback_id, rollback_approval_link_id, state, started_by, started_at, completed_at, paused_at, canceled_at, max_parallel, pause_reason, cancel_reason, progress_summary, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: patch_update_execution_host_packages; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.patch_update_execution_host_packages (id, execution_host_id, package_name, requested_version_snapshot, installed_version_before, installed_version_after, package_manager_family_snapshot, outcome, error_code, details, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: patch_update_execution_hosts; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.patch_update_execution_hosts (id, execution_id, plan_host_id, system_id_snapshot, system_hostname_snapshot, wave_index, state, selected_package_count, skip_reasons, error_details, started_at, completed_at, created_at, updated_at) FROM stdin;
1	1	1	1	host-one.example.test	0	succeeded	0	[]	{}	\N	\N	2026-01-15 12:00:00	2026-01-15 12:00:00
2	1	2	2	host-two.example.test	0	succeeded	0	[]	{}	\N	\N	2026-01-15 12:00:00	2026-01-15 12:00:00
\.


--
-- Data for Name: patch_update_execution_reboots; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.patch_update_execution_reboots (id, execution_id, execution_host_id, plan_id_snapshot, system_id_snapshot, system_hostname_snapshot, wave_index, state, reboot_policy_snapshot, reboot_window_id_snapshot, reboot_required_fact, decision_code, decision_details, scheduled_for_at, started_at, completed_at, created_at, updated_at, transport_kind, command_snapshot, exit_signal_kind, dispatch_details, verified_at, verification_details) FROM stdin;
\.


--
-- Data for Name: patch_update_execution_rollback_approvals; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.patch_update_execution_rollback_approvals (id, rollback_id, approval_id, requested_by, requested_at, frozen_plan_snapshot, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: patch_update_execution_rollback_hosts; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.patch_update_execution_rollback_hosts (id, rollback_id, execution_host_id, plan_host_id_snapshot, system_id_snapshot, system_hostname_snapshot, wave_index, execution_host_state_snapshot, state, refusal_reason, refusal_details, content_profile_snapshot, package_summary, evaluated_at, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: patch_update_execution_rollback_packages; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.patch_update_execution_rollback_packages (id, rollback_host_id, execution_host_package_id, package_name, package_manager_family_snapshot, installed_version_before_snapshot, installed_version_after_snapshot, requested_version_snapshot, target_rollback_version, package_outcome_snapshot, state, refusal_reason, refusal_details, content_evidence, evaluated_at, created_at, updated_at, command_plan) FROM stdin;
\.


--
-- Data for Name: patch_update_execution_rollbacks; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.patch_update_execution_rollbacks (id, execution_id, plan_id_snapshot, execution_state_snapshot, state, refusal_reason, refusal_details, feasibility_summary, evaluated_at, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: patch_update_executions; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.patch_update_executions (id, plan_id, state, started_by, started_at, completed_at, paused_at, canceled_at, max_parallel_per_wave, failure_threshold_percent, pause_reason, cancel_reason, plan_state_snapshot, policy_snapshot, execution_config_snapshot, progress_summary, created_at, updated_at) FROM stdin;
1	1	succeeded	1	2026-01-15 12:00:00	\N	\N	\N	5	\N	\N	\N	approved	{}	{}	{}	2026-01-15 12:00:00	2026-01-15 12:00:00
\.


--
-- Data for Name: patch_update_plan_approvals; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.patch_update_plan_approvals (id, plan_id, approval_id, requested_by, requested_at, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: patch_update_plan_hosts; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.patch_update_plan_hosts (id, plan_id, system_id, system_hostname_snapshot, policy_id_snapshot, policy_slug_snapshot, policy_resolution_kind, ring_id_snapshot, ring_slug_snapshot, ring_name_snapshot, ring_sort_order_snapshot, ring_source_tier, ring_resolution_status, wave_index, content_profile_state, content_profile_id_snapshot, content_profile_slug_snapshot, content_profile_display_name_snapshot, content_profile_package_family_snapshot, content_profile_conflict_snapshot, state, block_reasons, created_at, updated_at, selection_summary, preflight_summary) FROM stdin;
1	1	1	host-one.example.test	\N	\N	direct_host	\N	\N	\N	\N	\N	resolved	0	resolved	\N	\N	\N	\N	[]	planned	[]	2026-01-15 12:00:00	2026-01-15 12:00:00	\N	\N
2	1	2	host-two.example.test	\N	\N	direct_host	\N	\N	\N	\N	\N	resolved	0	resolved	\N	\N	\N	\N	[]	planned	[]	2026-01-15 12:00:00	2026-01-15 12:00:00	\N	\N
\.


--
-- Data for Name: patch_update_plan_preflight_snapshots; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.patch_update_plan_preflight_snapshots (id, plan_host_id, package_name, installed_version_at_preflight, package_manager_family_snapshot, content_availability_state, availability_details, evaluated_at, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: patch_update_plan_selected_packages; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.patch_update_plan_selected_packages (id, plan_host_id, package_name, installed_version_snapshot, available_version_snapshot, advisory_id_snapshot, advisory_source_kind_snapshot, advisory_class_snapshot, advisory_severity_snapshot, selection_reason, state, details, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: patch_update_plans; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.patch_update_plans (id, policy_id, name, description, state, scheduled_start_at, maintenance_window_id, reboot_window_id, policy_snapshot, ring_sequence_snapshot, request_snapshot, block_reasons, created_by, created_at, updated_at, archived_at, archived_by, archive_reason) FROM stdin;
1	\N	Fixture baseline plan	Targets host-one and host-two	approved	\N	\N	\N	{}	[]	{}	[]	1	2026-01-15 12:00:00	2026-01-15 12:00:00	\N	\N	\N
\.


--
-- Data for Name: recordings; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.recordings (id, session_id, user_id, system_id, file_path, size_bytes, frame_count, started_at, ended_at, retention_expires_at, status, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: refresh_tokens; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.refresh_tokens (id, token, user_id, is_valid, created_at, expires_at, updated_at) FROM stdin;
\.


--
-- Data for Name: repo_sources; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.repo_sources (id, system_id, name, url, repo_type, enabled, file_path, gpg_key_url, components, distribution, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: report_runs; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.report_runs (id, report_kind, triggered_by, triggered_by_user_id, triggered_by_username, format, filters_snapshot, row_count, state, error_message, started_at, completed_at, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: report_schedules; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.report_schedules (id, name, report_kind, cadence, filters_snapshot, format, enabled, next_run_at, last_run_at, last_run_id, last_run_state, created_by, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: revocation_work; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.revocation_work (id, reason, source, user_id, system_id, login, status, attempt_count, next_retry_at, last_error, created_at, updated_at, completed_at) FROM stdin;
\.


--
-- Data for Name: role; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.role (id, name, description, created_at, updated_at) FROM stdin;
1	admin	Full access to everything	2026-01-15 12:00:00	2026-01-15 12:00:00
2	maintainer	Manage systems, credentials, packages, jobs, SSH, vault	2026-01-15 12:00:00	2026-01-15 12:00:00
3	auditor	Read-only access to all data	2026-01-15 12:00:00	2026-01-15 12:00:00
\.


--
-- Data for Name: saved_views; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.saved_views (id, name, user_id, filters, is_default, is_shared, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: scheduler_job_locks; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.scheduler_job_locks (id, job_id, last_fired_at, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: session_approvals; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.session_approvals (id, requester_id, system_id, fleet_role_id, login, reason, state, approver_id, decision_reason, decided_at, expires_at, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: session_locks; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.session_locks (id, subject_user_id, subject_app_role_id, reason, created_by, created_at, released_at, released_by, updated_at) FROM stdin;
\.


--
-- Data for Name: sessions; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.sessions (id, user_id, system_id, fleet_role_id, login, cert_serial, client_ip, status, close_reason, started_at, last_activity_at, ended_at, max_expires_at, created_at, updated_at, transport, recording_retention_days) FROM stdin;
\.


--
-- Data for Name: smart_group_content_profile_subscriptions; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.smart_group_content_profile_subscriptions (id, smart_group_id, profile_id, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: smart_group_memberships; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.smart_group_memberships (id, smart_group_id, system_id, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: smart_groups; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.smart_groups (id, name, description, rule_json, enabled, created_by, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: ssh_host_keys; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.ssh_host_keys (id, system_id, hostname, key_type, public_key, fingerprint, verified, first_seen, last_seen, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: ssh_identity_settings; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.ssh_identity_settings (id, user_cert_ttl_seconds, default_principal, ca_identifier, created_at, updated_at) FROM stdin;
1	300	\N	praxis-9d178dcab276	2026-08-30 16:39:44.642627	2026-08-30 16:39:44.642627
\.


--
-- Data for Name: ssh_security_logs; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.ssh_security_logs (id, system_id, event_type, event_details, source_ip, username, success, "timestamp", created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: ssh_security_policies; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.ssh_security_policies (id, name, description, max_auth_tries, connection_timeout, idle_timeout, require_host_key_verification, minimum_key_size, allowed_auth_methods, allowed_ciphers, allowed_macs, allowed_kex, log_commands, log_file_transfers, created_at, updated_at, created_by) FROM stdin;
\.


--
-- Data for Name: system_audits; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.system_audits (id, system_id, audit_type, changed_by, changed_at, old_value, new_value, operation, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: system_metadata; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.system_metadata (id, system_id, cpu_arch, cpu_cores, memory_total, disk_total, environment_type, maintenance_window, owner_contact, location, ssh_port, last_connection, connection_status, created_at, updated_at, consecutive_failures, transport_failures, transport_cooldown_until, last_transport_error) FROM stdin;
\.


--
-- Data for Name: system_tag; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.system_tag (system_id, tag_id, created_at) FROM stdin;
\.


--
-- Data for Name: systems; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.systems (id, hostname, ip_address, distro_id, os_version, last_audited, status, group_id, credentials_id, ssh_security_policy_id, registered_at, registered_by, update_policy, last_successful_update, created_at, updated_at, ca_trust_deployed, ca_trust_deployed_at, principals_hook_deployed, principals_hook_deployed_at, agent_status, agent_cert_serial, agent_cert_fingerprint, agent_cert_expires_at, agent_revoked_at, agent_status_reason, agent_revocation_reason, agent_last_seen_at, agent_version, transport_preference) FROM stdin;
1	host-one.example.test	192.0.2.11	1	24.04	\N	active	1	1	\N	\N	\N	\N	\N	2026-01-15 12:00:00	2026-01-15 12:00:00	f	\N	f	\N	not_enrolled	\N	\N	\N	\N	\N	\N	\N	\N	auto
2	host-two.example.test	192.0.2.12	1	24.04	\N	active	1	1	\N	\N	\N	\N	\N	2026-01-15 12:00:00	2026-01-15 12:00:00	f	\N	f	\N	not_enrolled	\N	\N	\N	\N	\N	\N	\N	\N	auto
3	host-three.example.test	192.0.2.13	1	24.04	\N	active	1	1	\N	\N	\N	\N	\N	2026-01-15 12:00:00	2026-01-15 12:00:00	f	\N	f	\N	not_enrolled	\N	\N	\N	\N	\N	\N	\N	\N	auto
\.


--
-- Data for Name: tags; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.tags (id, name, color, created_by, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: totp_challenges; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.totp_challenges (id, user_id, created_at, expires_at, updated_at) FROM stdin;
\.


--
-- Data for Name: user; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public."user" (id, username, email, hashed_password, is_active, oidc_sub, created_at, updated_at, oidc_issuer, totp_secret, totp_enrolled_at, totp_recovery_codes) FROM stdin;
1	praxisadmin	praxisadmin@example.test	placeholder-not-a-hash	t	\N	2026-01-15 12:00:00	2026-01-15 12:00:00	\N	\N	\N	\N
2	fixture-operator	operator@example.test	placeholder-not-a-hash	t	\N	2026-01-15 12:00:00	2026-01-15 12:00:00	\N	\N	\N	\N
\.


--
-- Data for Name: user_role; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.user_role (user_id, role_id, created_at, updated_at) FROM stdin;
1	1	\N	\N
2	2	\N	\N
\.


--
-- Data for Name: vault_config; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.vault_config (id, is_internal, server_url, is_active, created_at, updated_at, created_by, last_health_check, health_status) FROM stdin;
\.


--
-- Name: access_bindings_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.access_bindings_id_seq', 1, false);


--
-- Name: access_grants_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.access_grants_id_seq', 1, false);


--
-- Name: access_requests_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.access_requests_id_seq', 1, false);


--
-- Name: access_review_items_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.access_review_items_id_seq', 1, false);


--
-- Name: access_reviews_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.access_reviews_id_seq', 1, false);


--
-- Name: activation_token_redemptions_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.activation_token_redemptions_id_seq', 1, false);


--
-- Name: activation_tokens_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.activation_tokens_id_seq', 1, false);


--
-- Name: airgap_bundle_signing_keys_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.airgap_bundle_signing_keys_id_seq', 1, false);


--
-- Name: airgap_bundles_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.airgap_bundles_id_seq', 1, false);


--
-- Name: airgap_import_trust_keys_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.airgap_import_trust_keys_id_seq', 1, false);


--
-- Name: airgap_imports_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.airgap_imports_id_seq', 1, false);


--
-- Name: alert_configs_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.alert_configs_id_seq', 1, false);


--
-- Name: alert_history_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.alert_history_id_seq', 1, false);


--
-- Name: app_settings_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.app_settings_id_seq', 4, true);


--
-- Name: audit_events_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.audit_events_id_seq', 4, true);


--
-- Name: audit_sink_deliveries_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.audit_sink_deliveries_id_seq', 1, false);


--
-- Name: audit_sinks_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.audit_sinks_id_seq', 1, false);


--
-- Name: baseline_checks_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.baseline_checks_id_seq', 1, false);


--
-- Name: baselines_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.baselines_id_seq', 1, false);


--
-- Name: ca_rotations_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.ca_rotations_id_seq', 1, false);


--
-- Name: command_approval_votes_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.command_approval_votes_id_seq', 1, false);


--
-- Name: command_approvals_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.command_approvals_id_seq', 1, false);


--
-- Name: command_distro_mapping_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.command_distro_mapping_id_seq', 1, false);


--
-- Name: command_execution_metrics_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.command_execution_metrics_id_seq', 1, false);


--
-- Name: command_execution_policies_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.command_execution_policies_id_seq', 1, false);


--
-- Name: command_execution_queue_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.command_execution_queue_id_seq', 1, false);


--
-- Name: command_execution_results_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.command_execution_results_id_seq', 1, false);


--
-- Name: command_execution_system_policies_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.command_execution_system_policies_id_seq', 1, false);


--
-- Name: command_execution_user_policies_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.command_execution_user_policies_id_seq', 1, false);


--
-- Name: command_resource_limits_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.command_resource_limits_id_seq', 1, false);


--
-- Name: command_template_distros_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.command_template_distros_id_seq', 1, false);


--
-- Name: command_templates_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.command_templates_id_seq', 1, false);


--
-- Name: command_validation_logs_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.command_validation_logs_id_seq', 1, false);


--
-- Name: command_validation_rules_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.command_validation_rules_id_seq', 1, true);


--
-- Name: command_whitelist_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.command_whitelist_id_seq', 2, true);


--
-- Name: compliance_policies_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.compliance_policies_id_seq', 1, false);


--
-- Name: compliance_policy_checks_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.compliance_policy_checks_id_seq', 1, false);


--
-- Name: compliance_policy_evidence_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.compliance_policy_evidence_id_seq', 1, false);


--
-- Name: compliance_remediation_execution_attempts_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.compliance_remediation_execution_attempts_id_seq', 1, false);


--
-- Name: compliance_remediation_plans_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.compliance_remediation_plans_id_seq', 1, false);


--
-- Name: compliance_remediation_requests_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.compliance_remediation_requests_id_seq', 1, false);


--
-- Name: content_channel_repos_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.content_channel_repos_id_seq', 1, false);


--
-- Name: content_channels_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.content_channels_id_seq', 1, false);


--
-- Name: content_profile_channels_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.content_profile_channels_id_seq', 1, false);


--
-- Name: content_profiles_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.content_profiles_id_seq', 1, false);


--
-- Name: credentials_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.credentials_id_seq', 1, true);


--
-- Name: distro_lifecycle_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.distro_lifecycle_id_seq', 33, true);


--
-- Name: distro_lifecycle_override_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.distro_lifecycle_override_id_seq', 1, false);


--
-- Name: distros_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.distros_id_seq', 1, true);


--
-- Name: file_transfer_audits_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.file_transfer_audits_id_seq', 1, false);


--
-- Name: fleet_operation_results_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.fleet_operation_results_id_seq', 1, false);


--
-- Name: fleet_operations_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.fleet_operations_id_seq', 1, false);


--
-- Name: fleet_roles_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.fleet_roles_id_seq', 3, true);


--
-- Name: global_connection_settings_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.global_connection_settings_id_seq', 1, true);


--
-- Name: group_content_profile_subscriptions_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.group_content_profile_subscriptions_id_seq', 1, false);


--
-- Name: groups_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.groups_id_seq', 1, true);


--
-- Name: host_content_profile_subscriptions_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.host_content_profile_subscriptions_id_seq', 1, false);


--
-- Name: host_facts_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.host_facts_id_seq', 1, false);


--
-- Name: host_mirror_serve_credentials_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.host_mirror_serve_credentials_id_seq', 1, false);


--
-- Name: host_mirror_trust_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.host_mirror_trust_id_seq', 1, false);


--
-- Name: host_user_states_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.host_user_states_id_seq', 1, false);


--
-- Name: job_history_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.job_history_id_seq', 1, false);


--
-- Name: jobs_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.jobs_id_seq', 1, false);


--
-- Name: lifecycle_notification_state_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.lifecycle_notification_state_id_seq', 1, false);


--
-- Name: maintenance_windows_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.maintenance_windows_id_seq', 1, false);


--
-- Name: mirror_alert_state_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.mirror_alert_state_id_seq', 1, false);


--
-- Name: mirror_repos_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.mirror_repos_id_seq', 1, false);


--
-- Name: mirror_signing_keys_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.mirror_signing_keys_id_seq', 1, false);


--
-- Name: mirror_sync_run_packages_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.mirror_sync_run_packages_id_seq', 1, false);


--
-- Name: mirror_sync_runs_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.mirror_sync_runs_id_seq', 1, false);


--
-- Name: mirror_upstream_keys_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.mirror_upstream_keys_id_seq', 1, false);


--
-- Name: notification_preferences_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.notification_preferences_id_seq', 1, false);


--
-- Name: notifications_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.notifications_id_seq', 1, false);


--
-- Name: oidc_login_state_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.oidc_login_state_id_seq', 1, false);


--
-- Name: oidc_provider_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.oidc_provider_id_seq', 1, false);


--
-- Name: package_history_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.package_history_id_seq', 1, false);


--
-- Name: package_updates_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.package_updates_id_seq', 1, false);


--
-- Name: packages_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.packages_id_seq', 1, false);


--
-- Name: patch_advisories_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.patch_advisories_id_seq', 1, false);


--
-- Name: patch_advisory_fixed_packages_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.patch_advisory_fixed_packages_id_seq', 1, false);


--
-- Name: patch_advisory_host_applicability_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.patch_advisory_host_applicability_id_seq', 1, false);


--
-- Name: patch_advisory_imports_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.patch_advisory_imports_id_seq', 1, false);


--
-- Name: patch_approval_votes_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.patch_approval_votes_id_seq', 1, false);


--
-- Name: patch_approvals_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.patch_approvals_id_seq', 1, false);


--
-- Name: patch_policies_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.patch_policies_id_seq', 1, false);


--
-- Name: patch_policy_group_bindings_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.patch_policy_group_bindings_id_seq', 1, false);


--
-- Name: patch_policy_host_bindings_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.patch_policy_host_bindings_id_seq', 1, false);


--
-- Name: patch_policy_ring_bindings_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.patch_policy_ring_bindings_id_seq', 1, false);


--
-- Name: patch_policy_smart_group_bindings_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.patch_policy_smart_group_bindings_id_seq', 1, false);


--
-- Name: patch_ring_gate_definitions_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.patch_ring_gate_definitions_id_seq', 1, false);


--
-- Name: patch_ring_gate_signals_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.patch_ring_gate_signals_id_seq', 1, false);


--
-- Name: patch_ring_group_bindings_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.patch_ring_group_bindings_id_seq', 1, false);


--
-- Name: patch_ring_host_bindings_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.patch_ring_host_bindings_id_seq', 1, false);


--
-- Name: patch_ring_smart_group_bindings_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.patch_ring_smart_group_bindings_id_seq', 1, false);


--
-- Name: patch_rings_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.patch_rings_id_seq', 1, false);


--
-- Name: patch_rollback_dispatch_host_packages_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.patch_rollback_dispatch_host_packages_id_seq', 1, false);


--
-- Name: patch_rollback_dispatch_hosts_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.patch_rollback_dispatch_hosts_id_seq', 1, false);


--
-- Name: patch_rollback_dispatch_runs_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.patch_rollback_dispatch_runs_id_seq', 1, false);


--
-- Name: patch_update_execution_host_packages_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.patch_update_execution_host_packages_id_seq', 1, false);


--
-- Name: patch_update_execution_hosts_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.patch_update_execution_hosts_id_seq', 2, true);


--
-- Name: patch_update_execution_reboots_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.patch_update_execution_reboots_id_seq', 1, false);


--
-- Name: patch_update_execution_rollback_approvals_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.patch_update_execution_rollback_approvals_id_seq', 1, false);


--
-- Name: patch_update_execution_rollback_hosts_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.patch_update_execution_rollback_hosts_id_seq', 1, false);


--
-- Name: patch_update_execution_rollback_packages_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.patch_update_execution_rollback_packages_id_seq', 1, false);


--
-- Name: patch_update_execution_rollbacks_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.patch_update_execution_rollbacks_id_seq', 1, false);


--
-- Name: patch_update_executions_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.patch_update_executions_id_seq', 1, true);


--
-- Name: patch_update_plan_approvals_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.patch_update_plan_approvals_id_seq', 1, false);


--
-- Name: patch_update_plan_hosts_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.patch_update_plan_hosts_id_seq', 2, true);


--
-- Name: patch_update_plan_preflight_snapshots_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.patch_update_plan_preflight_snapshots_id_seq', 1, false);


--
-- Name: patch_update_plan_selected_packages_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.patch_update_plan_selected_packages_id_seq', 1, false);


--
-- Name: patch_update_plans_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.patch_update_plans_id_seq', 1, true);


--
-- Name: recordings_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.recordings_id_seq', 1, false);


--
-- Name: refresh_tokens_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.refresh_tokens_id_seq', 1, false);


--
-- Name: repo_sources_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.repo_sources_id_seq', 1, false);


--
-- Name: report_runs_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.report_runs_id_seq', 1, false);


--
-- Name: report_schedules_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.report_schedules_id_seq', 1, false);


--
-- Name: revocation_work_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.revocation_work_id_seq', 1, false);


--
-- Name: role_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.role_id_seq', 3, true);


--
-- Name: saved_views_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.saved_views_id_seq', 1, false);


--
-- Name: scheduler_job_locks_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.scheduler_job_locks_id_seq', 1, false);


--
-- Name: session_approvals_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.session_approvals_id_seq', 1, false);


--
-- Name: session_locks_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.session_locks_id_seq', 1, false);


--
-- Name: sessions_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.sessions_id_seq', 1, false);


--
-- Name: smart_group_content_profile_subscriptions_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.smart_group_content_profile_subscriptions_id_seq', 1, false);


--
-- Name: smart_group_memberships_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.smart_group_memberships_id_seq', 1, false);


--
-- Name: smart_groups_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.smart_groups_id_seq', 1, false);


--
-- Name: ssh_host_keys_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.ssh_host_keys_id_seq', 1, false);


--
-- Name: ssh_identity_settings_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.ssh_identity_settings_id_seq', 1, true);


--
-- Name: ssh_security_logs_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.ssh_security_logs_id_seq', 1, false);


--
-- Name: ssh_security_policies_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.ssh_security_policies_id_seq', 1, false);


--
-- Name: system_audits_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.system_audits_id_seq', 1, false);


--
-- Name: system_metadata_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.system_metadata_id_seq', 1, false);


--
-- Name: systems_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.systems_id_seq', 3, true);


--
-- Name: tags_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.tags_id_seq', 1, false);


--
-- Name: totp_challenges_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.totp_challenges_id_seq', 1, false);


--
-- Name: user_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.user_id_seq', 2, true);


--
-- Name: vault_config_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.vault_config_id_seq', 1, false);


--
-- Name: access_bindings access_bindings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.access_bindings
    ADD CONSTRAINT access_bindings_pkey PRIMARY KEY (id);


--
-- Name: access_grants access_grants_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.access_grants
    ADD CONSTRAINT access_grants_pkey PRIMARY KEY (id);


--
-- Name: access_requests access_requests_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.access_requests
    ADD CONSTRAINT access_requests_pkey PRIMARY KEY (id);


--
-- Name: access_review_items access_review_items_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.access_review_items
    ADD CONSTRAINT access_review_items_pkey PRIMARY KEY (id);


--
-- Name: access_reviews access_reviews_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.access_reviews
    ADD CONSTRAINT access_reviews_pkey PRIMARY KEY (id);


--
-- Name: activation_token_redemptions activation_token_redemptions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.activation_token_redemptions
    ADD CONSTRAINT activation_token_redemptions_pkey PRIMARY KEY (id);


--
-- Name: activation_tokens activation_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.activation_tokens
    ADD CONSTRAINT activation_tokens_pkey PRIMARY KEY (id);


--
-- Name: airgap_bundle_signing_keys airgap_bundle_signing_keys_fingerprint_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.airgap_bundle_signing_keys
    ADD CONSTRAINT airgap_bundle_signing_keys_fingerprint_unique UNIQUE (gpg_fingerprint);


--
-- Name: airgap_bundle_signing_keys airgap_bundle_signing_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.airgap_bundle_signing_keys
    ADD CONSTRAINT airgap_bundle_signing_keys_pkey PRIMARY KEY (id);


--
-- Name: airgap_bundles airgap_bundles_bundle_id_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.airgap_bundles
    ADD CONSTRAINT airgap_bundles_bundle_id_unique UNIQUE (bundle_id);


--
-- Name: airgap_bundles airgap_bundles_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.airgap_bundles
    ADD CONSTRAINT airgap_bundles_pkey PRIMARY KEY (id);


--
-- Name: airgap_import_trust_keys airgap_import_trust_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.airgap_import_trust_keys
    ADD CONSTRAINT airgap_import_trust_keys_pkey PRIMARY KEY (id);


--
-- Name: airgap_imports airgap_imports_bundle_id_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.airgap_imports
    ADD CONSTRAINT airgap_imports_bundle_id_unique UNIQUE (bundle_id);


--
-- Name: airgap_imports airgap_imports_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.airgap_imports
    ADD CONSTRAINT airgap_imports_pkey PRIMARY KEY (id);


--
-- Name: alembic_version alembic_version_pkc; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alembic_version
    ADD CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num);


--
-- Name: alert_configs alert_configs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alert_configs
    ADD CONSTRAINT alert_configs_pkey PRIMARY KEY (id);


--
-- Name: alert_history alert_history_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alert_history
    ADD CONSTRAINT alert_history_pkey PRIMARY KEY (id);


--
-- Name: app_settings app_settings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.app_settings
    ADD CONSTRAINT app_settings_pkey PRIMARY KEY (id);


--
-- Name: audit_events audit_events_event_uuid_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_events
    ADD CONSTRAINT audit_events_event_uuid_key UNIQUE (event_uuid);


--
-- Name: audit_events audit_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_events
    ADD CONSTRAINT audit_events_pkey PRIMARY KEY (id);


--
-- Name: audit_sink_deliveries audit_sink_deliveries_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_sink_deliveries
    ADD CONSTRAINT audit_sink_deliveries_pkey PRIMARY KEY (id);


--
-- Name: audit_sinks audit_sinks_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_sinks
    ADD CONSTRAINT audit_sinks_name_key UNIQUE (name);


--
-- Name: audit_sinks audit_sinks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_sinks
    ADD CONSTRAINT audit_sinks_pkey PRIMARY KEY (id);


--
-- Name: baseline_checks baseline_checks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.baseline_checks
    ADD CONSTRAINT baseline_checks_pkey PRIMARY KEY (id);


--
-- Name: baselines baselines_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.baselines
    ADD CONSTRAINT baselines_name_key UNIQUE (name);


--
-- Name: baselines baselines_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.baselines
    ADD CONSTRAINT baselines_pkey PRIMARY KEY (id);


--
-- Name: ca_rotations ca_rotations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ca_rotations
    ADD CONSTRAINT ca_rotations_pkey PRIMARY KEY (id);


--
-- Name: command_approval_votes command_approval_votes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.command_approval_votes
    ADD CONSTRAINT command_approval_votes_pkey PRIMARY KEY (id);


--
-- Name: command_approvals command_approvals_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.command_approvals
    ADD CONSTRAINT command_approvals_pkey PRIMARY KEY (id);


--
-- Name: command_distro_mapping command_distro_mapping_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.command_distro_mapping
    ADD CONSTRAINT command_distro_mapping_pkey PRIMARY KEY (id);


--
-- Name: command_execution_metrics command_execution_metrics_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.command_execution_metrics
    ADD CONSTRAINT command_execution_metrics_pkey PRIMARY KEY (id);


--
-- Name: command_execution_policies command_execution_policies_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.command_execution_policies
    ADD CONSTRAINT command_execution_policies_pkey PRIMARY KEY (id);


--
-- Name: command_execution_queue command_execution_queue_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.command_execution_queue
    ADD CONSTRAINT command_execution_queue_pkey PRIMARY KEY (id);


--
-- Name: command_execution_results command_execution_results_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.command_execution_results
    ADD CONSTRAINT command_execution_results_pkey PRIMARY KEY (id);


--
-- Name: command_execution_system_policies command_execution_system_policies_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.command_execution_system_policies
    ADD CONSTRAINT command_execution_system_policies_pkey PRIMARY KEY (id);


--
-- Name: command_execution_user_policies command_execution_user_policies_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.command_execution_user_policies
    ADD CONSTRAINT command_execution_user_policies_pkey PRIMARY KEY (id);


--
-- Name: command_resource_limits command_resource_limits_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.command_resource_limits
    ADD CONSTRAINT command_resource_limits_pkey PRIMARY KEY (id);


--
-- Name: command_template_distros command_template_distros_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.command_template_distros
    ADD CONSTRAINT command_template_distros_pkey PRIMARY KEY (id);


--
-- Name: command_templates command_templates_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.command_templates
    ADD CONSTRAINT command_templates_pkey PRIMARY KEY (id);


--
-- Name: command_validation_logs command_validation_logs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.command_validation_logs
    ADD CONSTRAINT command_validation_logs_pkey PRIMARY KEY (id);


--
-- Name: command_validation_rules command_validation_rules_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.command_validation_rules
    ADD CONSTRAINT command_validation_rules_pkey PRIMARY KEY (id);


--
-- Name: command_whitelist command_whitelist_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.command_whitelist
    ADD CONSTRAINT command_whitelist_pkey PRIMARY KEY (id);


--
-- Name: compliance_policies compliance_policies_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.compliance_policies
    ADD CONSTRAINT compliance_policies_pkey PRIMARY KEY (id);


--
-- Name: compliance_policy_checks compliance_policy_checks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.compliance_policy_checks
    ADD CONSTRAINT compliance_policy_checks_pkey PRIMARY KEY (id);


--
-- Name: compliance_policy_evidence compliance_policy_evidence_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.compliance_policy_evidence
    ADD CONSTRAINT compliance_policy_evidence_pkey PRIMARY KEY (id);


--
-- Name: compliance_remediation_execution_attempts compliance_remediation_execution_attempts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.compliance_remediation_execution_attempts
    ADD CONSTRAINT compliance_remediation_execution_attempts_pkey PRIMARY KEY (id);


--
-- Name: compliance_remediation_plans compliance_remediation_plans_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.compliance_remediation_plans
    ADD CONSTRAINT compliance_remediation_plans_pkey PRIMARY KEY (id);


--
-- Name: compliance_remediation_requests compliance_remediation_requests_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.compliance_remediation_requests
    ADD CONSTRAINT compliance_remediation_requests_pkey PRIMARY KEY (id);


--
-- Name: content_channel_repos content_channel_repos_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.content_channel_repos
    ADD CONSTRAINT content_channel_repos_pkey PRIMARY KEY (id);


--
-- Name: content_channel_repos content_channel_repos_unique_triple; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.content_channel_repos
    ADD CONSTRAINT content_channel_repos_unique_triple UNIQUE (channel_id, mirror_id, suite_override);


--
-- Name: content_channels content_channels_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.content_channels
    ADD CONSTRAINT content_channels_pkey PRIMARY KEY (id);


--
-- Name: content_channels content_channels_slug_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.content_channels
    ADD CONSTRAINT content_channels_slug_unique UNIQUE (slug);


--
-- Name: content_profile_channels content_profile_channels_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.content_profile_channels
    ADD CONSTRAINT content_profile_channels_pkey PRIMARY KEY (id);


--
-- Name: content_profile_channels content_profile_channels_unique_pair; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.content_profile_channels
    ADD CONSTRAINT content_profile_channels_unique_pair UNIQUE (profile_id, channel_id);


--
-- Name: content_profiles content_profiles_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.content_profiles
    ADD CONSTRAINT content_profiles_pkey PRIMARY KEY (id);


--
-- Name: content_profiles content_profiles_slug_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.content_profiles
    ADD CONSTRAINT content_profiles_slug_unique UNIQUE (slug);


--
-- Name: credentials credentials_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.credentials
    ADD CONSTRAINT credentials_name_key UNIQUE (name);


--
-- Name: credentials credentials_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.credentials
    ADD CONSTRAINT credentials_pkey PRIMARY KEY (id);


--
-- Name: distro_lifecycle_override distro_lifecycle_override_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.distro_lifecycle_override
    ADD CONSTRAINT distro_lifecycle_override_pkey PRIMARY KEY (id);


--
-- Name: distro_lifecycle_override distro_lifecycle_override_unique_per_scope; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.distro_lifecycle_override
    ADD CONSTRAINT distro_lifecycle_override_unique_per_scope UNIQUE (scope_type, scope_id, distro_id, release);


--
-- Name: distro_lifecycle distro_lifecycle_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.distro_lifecycle
    ADD CONSTRAINT distro_lifecycle_pkey PRIMARY KEY (id);


--
-- Name: distro_lifecycle distro_lifecycle_unique_per_kind; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.distro_lifecycle
    ADD CONSTRAINT distro_lifecycle_unique_per_kind UNIQUE (distro_id, release, support_kind);


--
-- Name: distros distros_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.distros
    ADD CONSTRAINT distros_pkey PRIMARY KEY (id);


--
-- Name: file_transfer_audits file_transfer_audits_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.file_transfer_audits
    ADD CONSTRAINT file_transfer_audits_pkey PRIMARY KEY (id);


--
-- Name: fleet_operation_results fleet_operation_results_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.fleet_operation_results
    ADD CONSTRAINT fleet_operation_results_pkey PRIMARY KEY (id);


--
-- Name: fleet_operations fleet_operations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.fleet_operations
    ADD CONSTRAINT fleet_operations_pkey PRIMARY KEY (id);


--
-- Name: fleet_roles fleet_roles_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.fleet_roles
    ADD CONSTRAINT fleet_roles_name_key UNIQUE (name);


--
-- Name: fleet_roles fleet_roles_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.fleet_roles
    ADD CONSTRAINT fleet_roles_pkey PRIMARY KEY (id);


--
-- Name: global_connection_settings global_connection_settings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.global_connection_settings
    ADD CONSTRAINT global_connection_settings_pkey PRIMARY KEY (id);


--
-- Name: group_content_profile_subscriptions group_content_profile_subs_unique_pair; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.group_content_profile_subscriptions
    ADD CONSTRAINT group_content_profile_subs_unique_pair UNIQUE (group_id, profile_id);


--
-- Name: group_content_profile_subscriptions group_content_profile_subscriptions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.group_content_profile_subscriptions
    ADD CONSTRAINT group_content_profile_subscriptions_pkey PRIMARY KEY (id);


--
-- Name: groups groups_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.groups
    ADD CONSTRAINT groups_name_key UNIQUE (name);


--
-- Name: groups groups_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.groups
    ADD CONSTRAINT groups_pkey PRIMARY KEY (id);


--
-- Name: host_content_profile_subscriptions host_content_profile_subs_unique_pair; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.host_content_profile_subscriptions
    ADD CONSTRAINT host_content_profile_subs_unique_pair UNIQUE (host_id, profile_id);


--
-- Name: host_content_profile_subscriptions host_content_profile_subscriptions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.host_content_profile_subscriptions
    ADD CONSTRAINT host_content_profile_subscriptions_pkey PRIMARY KEY (id);


--
-- Name: host_facts host_facts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.host_facts
    ADD CONSTRAINT host_facts_pkey PRIMARY KEY (id);


--
-- Name: host_facts host_facts_system_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.host_facts
    ADD CONSTRAINT host_facts_system_id_key UNIQUE (system_id);


--
-- Name: host_mirror_serve_credentials host_mirror_serve_credentials_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.host_mirror_serve_credentials
    ADD CONSTRAINT host_mirror_serve_credentials_pkey PRIMARY KEY (id);


--
-- Name: host_mirror_trust host_mirror_trust_host_mirror_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.host_mirror_trust
    ADD CONSTRAINT host_mirror_trust_host_mirror_unique UNIQUE (host_id, mirror_id);


--
-- Name: host_mirror_trust host_mirror_trust_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.host_mirror_trust
    ADD CONSTRAINT host_mirror_trust_pkey PRIMARY KEY (id);


--
-- Name: host_user_states host_user_states_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.host_user_states
    ADD CONSTRAINT host_user_states_pkey PRIMARY KEY (id);


--
-- Name: job_history job_history_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.job_history
    ADD CONSTRAINT job_history_pkey PRIMARY KEY (id);


--
-- Name: jobs jobs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.jobs
    ADD CONSTRAINT jobs_pkey PRIMARY KEY (id);


--
-- Name: lifecycle_notification_state lifecycle_notification_state_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.lifecycle_notification_state
    ADD CONSTRAINT lifecycle_notification_state_pkey PRIMARY KEY (id);


--
-- Name: lifecycle_notification_state lifecycle_notification_state_unique_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.lifecycle_notification_state
    ADD CONSTRAINT lifecycle_notification_state_unique_key UNIQUE (system_id, event_type, threshold_days, effective_eol_date);


--
-- Name: maintenance_windows maintenance_windows_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.maintenance_windows
    ADD CONSTRAINT maintenance_windows_pkey PRIMARY KEY (id);


--
-- Name: mirror_alert_state mirror_alert_state_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mirror_alert_state
    ADD CONSTRAINT mirror_alert_state_pkey PRIMARY KEY (id);


--
-- Name: mirror_alert_state mirror_alert_state_unique_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mirror_alert_state
    ADD CONSTRAINT mirror_alert_state_unique_key UNIQUE (mirror_repo_id, event_type);


--
-- Name: mirror_repos mirror_repos_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mirror_repos
    ADD CONSTRAINT mirror_repos_pkey PRIMARY KEY (id);


--
-- Name: mirror_repos mirror_repos_slug_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mirror_repos
    ADD CONSTRAINT mirror_repos_slug_unique UNIQUE (slug);


--
-- Name: mirror_signing_keys mirror_signing_keys_fingerprint_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mirror_signing_keys
    ADD CONSTRAINT mirror_signing_keys_fingerprint_unique UNIQUE (gpg_fingerprint);


--
-- Name: mirror_signing_keys mirror_signing_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mirror_signing_keys
    ADD CONSTRAINT mirror_signing_keys_pkey PRIMARY KEY (id);


--
-- Name: mirror_sync_run_packages mirror_sync_run_packages_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mirror_sync_run_packages
    ADD CONSTRAINT mirror_sync_run_packages_pkey PRIMARY KEY (id);


--
-- Name: mirror_sync_runs mirror_sync_runs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mirror_sync_runs
    ADD CONSTRAINT mirror_sync_runs_pkey PRIMARY KEY (id);


--
-- Name: mirror_upstream_keys mirror_upstream_keys_fingerprint_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mirror_upstream_keys
    ADD CONSTRAINT mirror_upstream_keys_fingerprint_unique UNIQUE (gpg_fingerprint);


--
-- Name: mirror_upstream_keys mirror_upstream_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mirror_upstream_keys
    ADD CONSTRAINT mirror_upstream_keys_pkey PRIMARY KEY (id);


--
-- Name: notification_preferences notification_preferences_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.notification_preferences
    ADD CONSTRAINT notification_preferences_pkey PRIMARY KEY (id);


--
-- Name: notification_preferences notification_preferences_user_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.notification_preferences
    ADD CONSTRAINT notification_preferences_user_id_key UNIQUE (user_id);


--
-- Name: notifications notifications_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.notifications
    ADD CONSTRAINT notifications_pkey PRIMARY KEY (id);


--
-- Name: oidc_login_state oidc_login_state_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oidc_login_state
    ADD CONSTRAINT oidc_login_state_pkey PRIMARY KEY (id);


--
-- Name: oidc_provider oidc_provider_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oidc_provider
    ADD CONSTRAINT oidc_provider_pkey PRIMARY KEY (id);


--
-- Name: package_history package_history_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.package_history
    ADD CONSTRAINT package_history_pkey PRIMARY KEY (id);


--
-- Name: package_updates package_updates_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.package_updates
    ADD CONSTRAINT package_updates_pkey PRIMARY KEY (id);


--
-- Name: packages packages_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.packages
    ADD CONSTRAINT packages_pkey PRIMARY KEY (id);


--
-- Name: patch_advisories patch_advisories_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_advisories
    ADD CONSTRAINT patch_advisories_pkey PRIMARY KEY (id);


--
-- Name: patch_advisory_fixed_packages patch_advisory_fixed_packages_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_advisory_fixed_packages
    ADD CONSTRAINT patch_advisory_fixed_packages_pkey PRIMARY KEY (id);


--
-- Name: patch_advisory_host_applicability patch_advisory_host_applicability_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_advisory_host_applicability
    ADD CONSTRAINT patch_advisory_host_applicability_pkey PRIMARY KEY (id);


--
-- Name: patch_advisory_imports patch_advisory_imports_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_advisory_imports
    ADD CONSTRAINT patch_advisory_imports_pkey PRIMARY KEY (id);


--
-- Name: patch_approval_votes patch_approval_votes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_approval_votes
    ADD CONSTRAINT patch_approval_votes_pkey PRIMARY KEY (id);


--
-- Name: patch_approvals patch_approvals_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_approvals
    ADD CONSTRAINT patch_approvals_pkey PRIMARY KEY (id);


--
-- Name: patch_policies patch_policies_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_policies
    ADD CONSTRAINT patch_policies_pkey PRIMARY KEY (id);


--
-- Name: patch_policy_group_bindings patch_policy_group_bindings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_policy_group_bindings
    ADD CONSTRAINT patch_policy_group_bindings_pkey PRIMARY KEY (id);


--
-- Name: patch_policy_host_bindings patch_policy_host_bindings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_policy_host_bindings
    ADD CONSTRAINT patch_policy_host_bindings_pkey PRIMARY KEY (id);


--
-- Name: patch_policy_ring_bindings patch_policy_ring_bindings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_policy_ring_bindings
    ADD CONSTRAINT patch_policy_ring_bindings_pkey PRIMARY KEY (id);


--
-- Name: patch_policy_smart_group_bindings patch_policy_smart_group_bindings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_policy_smart_group_bindings
    ADD CONSTRAINT patch_policy_smart_group_bindings_pkey PRIMARY KEY (id);


--
-- Name: patch_ring_gate_definitions patch_ring_gate_definitions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_ring_gate_definitions
    ADD CONSTRAINT patch_ring_gate_definitions_pkey PRIMARY KEY (id);


--
-- Name: patch_ring_gate_signals patch_ring_gate_signals_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_ring_gate_signals
    ADD CONSTRAINT patch_ring_gate_signals_pkey PRIMARY KEY (id);


--
-- Name: patch_ring_group_bindings patch_ring_group_bindings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_ring_group_bindings
    ADD CONSTRAINT patch_ring_group_bindings_pkey PRIMARY KEY (id);


--
-- Name: patch_ring_host_bindings patch_ring_host_bindings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_ring_host_bindings
    ADD CONSTRAINT patch_ring_host_bindings_pkey PRIMARY KEY (id);


--
-- Name: patch_ring_smart_group_bindings patch_ring_smart_group_bindings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_ring_smart_group_bindings
    ADD CONSTRAINT patch_ring_smart_group_bindings_pkey PRIMARY KEY (id);


--
-- Name: patch_rings patch_rings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_rings
    ADD CONSTRAINT patch_rings_pkey PRIMARY KEY (id);


--
-- Name: patch_rollback_dispatch_host_packages patch_rollback_dispatch_host_packages_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_rollback_dispatch_host_packages
    ADD CONSTRAINT patch_rollback_dispatch_host_packages_pkey PRIMARY KEY (id);


--
-- Name: patch_rollback_dispatch_hosts patch_rollback_dispatch_hosts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_rollback_dispatch_hosts
    ADD CONSTRAINT patch_rollback_dispatch_hosts_pkey PRIMARY KEY (id);


--
-- Name: patch_rollback_dispatch_runs patch_rollback_dispatch_runs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_rollback_dispatch_runs
    ADD CONSTRAINT patch_rollback_dispatch_runs_pkey PRIMARY KEY (id);


--
-- Name: patch_update_execution_host_packages patch_update_execution_host_packages_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_update_execution_host_packages
    ADD CONSTRAINT patch_update_execution_host_packages_pkey PRIMARY KEY (id);


--
-- Name: patch_update_execution_hosts patch_update_execution_hosts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_update_execution_hosts
    ADD CONSTRAINT patch_update_execution_hosts_pkey PRIMARY KEY (id);


--
-- Name: patch_update_execution_reboots patch_update_execution_reboots_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_update_execution_reboots
    ADD CONSTRAINT patch_update_execution_reboots_pkey PRIMARY KEY (id);


--
-- Name: patch_update_execution_rollback_approvals patch_update_execution_rollback_approvals_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_update_execution_rollback_approvals
    ADD CONSTRAINT patch_update_execution_rollback_approvals_pkey PRIMARY KEY (id);


--
-- Name: patch_update_execution_rollback_hosts patch_update_execution_rollback_hosts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_update_execution_rollback_hosts
    ADD CONSTRAINT patch_update_execution_rollback_hosts_pkey PRIMARY KEY (id);


--
-- Name: patch_update_execution_rollback_packages patch_update_execution_rollback_packages_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_update_execution_rollback_packages
    ADD CONSTRAINT patch_update_execution_rollback_packages_pkey PRIMARY KEY (id);


--
-- Name: patch_update_execution_rollbacks patch_update_execution_rollbacks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_update_execution_rollbacks
    ADD CONSTRAINT patch_update_execution_rollbacks_pkey PRIMARY KEY (id);


--
-- Name: patch_update_executions patch_update_executions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_update_executions
    ADD CONSTRAINT patch_update_executions_pkey PRIMARY KEY (id);


--
-- Name: patch_update_plan_approvals patch_update_plan_approvals_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_update_plan_approvals
    ADD CONSTRAINT patch_update_plan_approvals_pkey PRIMARY KEY (id);


--
-- Name: patch_update_plan_hosts patch_update_plan_hosts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_update_plan_hosts
    ADD CONSTRAINT patch_update_plan_hosts_pkey PRIMARY KEY (id);


--
-- Name: patch_update_plan_preflight_snapshots patch_update_plan_preflight_snapshots_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_update_plan_preflight_snapshots
    ADD CONSTRAINT patch_update_plan_preflight_snapshots_pkey PRIMARY KEY (id);


--
-- Name: patch_update_plan_selected_packages patch_update_plan_selected_packages_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_update_plan_selected_packages
    ADD CONSTRAINT patch_update_plan_selected_packages_pkey PRIMARY KEY (id);


--
-- Name: patch_update_plans patch_update_plans_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_update_plans
    ADD CONSTRAINT patch_update_plans_pkey PRIMARY KEY (id);


--
-- Name: recordings recordings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.recordings
    ADD CONSTRAINT recordings_pkey PRIMARY KEY (id);


--
-- Name: recordings recordings_session_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.recordings
    ADD CONSTRAINT recordings_session_id_key UNIQUE (session_id);


--
-- Name: refresh_tokens refresh_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.refresh_tokens
    ADD CONSTRAINT refresh_tokens_pkey PRIMARY KEY (id);


--
-- Name: repo_sources repo_sources_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.repo_sources
    ADD CONSTRAINT repo_sources_pkey PRIMARY KEY (id);


--
-- Name: report_runs report_runs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.report_runs
    ADD CONSTRAINT report_runs_pkey PRIMARY KEY (id);


--
-- Name: report_schedules report_schedules_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.report_schedules
    ADD CONSTRAINT report_schedules_pkey PRIMARY KEY (id);


--
-- Name: revocation_work revocation_work_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.revocation_work
    ADD CONSTRAINT revocation_work_pkey PRIMARY KEY (id);


--
-- Name: role role_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role
    ADD CONSTRAINT role_name_key UNIQUE (name);


--
-- Name: role role_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role
    ADD CONSTRAINT role_pkey PRIMARY KEY (id);


--
-- Name: saved_views saved_views_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.saved_views
    ADD CONSTRAINT saved_views_pkey PRIMARY KEY (id);


--
-- Name: scheduler_job_locks scheduler_job_locks_job_id_uniq; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scheduler_job_locks
    ADD CONSTRAINT scheduler_job_locks_job_id_uniq UNIQUE (job_id);


--
-- Name: scheduler_job_locks scheduler_job_locks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scheduler_job_locks
    ADD CONSTRAINT scheduler_job_locks_pkey PRIMARY KEY (id);


--
-- Name: session_approvals session_approvals_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.session_approvals
    ADD CONSTRAINT session_approvals_pkey PRIMARY KEY (id);


--
-- Name: session_locks session_locks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.session_locks
    ADD CONSTRAINT session_locks_pkey PRIMARY KEY (id);


--
-- Name: sessions sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sessions
    ADD CONSTRAINT sessions_pkey PRIMARY KEY (id);


--
-- Name: smart_group_content_profile_subscriptions smart_group_content_profile_subs_unique_pair; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.smart_group_content_profile_subscriptions
    ADD CONSTRAINT smart_group_content_profile_subs_unique_pair UNIQUE (smart_group_id, profile_id);


--
-- Name: smart_group_content_profile_subscriptions smart_group_content_profile_subscriptions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.smart_group_content_profile_subscriptions
    ADD CONSTRAINT smart_group_content_profile_subscriptions_pkey PRIMARY KEY (id);


--
-- Name: smart_group_memberships smart_group_memberships_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.smart_group_memberships
    ADD CONSTRAINT smart_group_memberships_pkey PRIMARY KEY (id);


--
-- Name: smart_groups smart_groups_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.smart_groups
    ADD CONSTRAINT smart_groups_name_key UNIQUE (name);


--
-- Name: smart_groups smart_groups_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.smart_groups
    ADD CONSTRAINT smart_groups_pkey PRIMARY KEY (id);


--
-- Name: ssh_host_keys ssh_host_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ssh_host_keys
    ADD CONSTRAINT ssh_host_keys_pkey PRIMARY KEY (id);


--
-- Name: ssh_identity_settings ssh_identity_settings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ssh_identity_settings
    ADD CONSTRAINT ssh_identity_settings_pkey PRIMARY KEY (id);


--
-- Name: ssh_security_logs ssh_security_logs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ssh_security_logs
    ADD CONSTRAINT ssh_security_logs_pkey PRIMARY KEY (id);


--
-- Name: ssh_security_policies ssh_security_policies_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ssh_security_policies
    ADD CONSTRAINT ssh_security_policies_name_key UNIQUE (name);


--
-- Name: ssh_security_policies ssh_security_policies_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ssh_security_policies
    ADD CONSTRAINT ssh_security_policies_pkey PRIMARY KEY (id);


--
-- Name: system_audits system_audits_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.system_audits
    ADD CONSTRAINT system_audits_pkey PRIMARY KEY (id);


--
-- Name: system_metadata system_metadata_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.system_metadata
    ADD CONSTRAINT system_metadata_pkey PRIMARY KEY (id);


--
-- Name: system_metadata system_metadata_system_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.system_metadata
    ADD CONSTRAINT system_metadata_system_id_key UNIQUE (system_id);


--
-- Name: system_tag system_tag_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.system_tag
    ADD CONSTRAINT system_tag_pkey PRIMARY KEY (system_id, tag_id);


--
-- Name: systems systems_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.systems
    ADD CONSTRAINT systems_pkey PRIMARY KEY (id);


--
-- Name: tags tags_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tags
    ADD CONSTRAINT tags_pkey PRIMARY KEY (id);


--
-- Name: totp_challenges totp_challenges_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.totp_challenges
    ADD CONSTRAINT totp_challenges_pkey PRIMARY KEY (id);


--
-- Name: access_grants uq_access_grant_user_system_role_login; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.access_grants
    ADD CONSTRAINT uq_access_grant_user_system_role_login UNIQUE (user_id, system_id, fleet_role_id, login);


--
-- Name: activation_token_redemptions uq_activation_redemptions_token_fingerprint; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.activation_token_redemptions
    ADD CONSTRAINT uq_activation_redemptions_token_fingerprint UNIQUE (activation_token_id, host_fingerprint_hash);


--
-- Name: activation_token_redemptions uq_activation_redemptions_token_system; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.activation_token_redemptions
    ADD CONSTRAINT uq_activation_redemptions_token_system UNIQUE (activation_token_id, system_id);


--
-- Name: command_approval_votes uq_command_approval_votes_approval_user; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.command_approval_votes
    ADD CONSTRAINT uq_command_approval_votes_approval_user UNIQUE (approval_id, user_id);


--
-- Name: compliance_policies uq_compliance_policies_slug; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.compliance_policies
    ADD CONSTRAINT uq_compliance_policies_slug UNIQUE (slug);


--
-- Name: compliance_policy_checks uq_compliance_policy_checks_policy_slug; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.compliance_policy_checks
    ADD CONSTRAINT uq_compliance_policy_checks_policy_slug UNIQUE (policy_id, slug);


--
-- Name: host_user_states uq_host_user_state_system_login; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.host_user_states
    ADD CONSTRAINT uq_host_user_state_system_login UNIQUE (system_id, login);


--
-- Name: mirror_sync_run_packages uq_mirror_sync_run_packages_target; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mirror_sync_run_packages
    ADD CONSTRAINT uq_mirror_sync_run_packages_target UNIQUE (mirror_sync_run_id, package_name, version, arch);


--
-- Name: patch_advisories uq_patch_advisories_source_id; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_advisories
    ADD CONSTRAINT uq_patch_advisories_source_id UNIQUE (source_kind, source_advisory_id);


--
-- Name: patch_advisory_fixed_packages uq_patch_advisory_fixed_packages_target; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_advisory_fixed_packages
    ADD CONSTRAINT uq_patch_advisory_fixed_packages_target UNIQUE (advisory_id, distro_id, distro_release, package_name);


--
-- Name: patch_advisory_host_applicability uq_patch_advisory_host_applicability_target; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_advisory_host_applicability
    ADD CONSTRAINT uq_patch_advisory_host_applicability_target UNIQUE (system_id, advisory_id, package_name);


--
-- Name: patch_approval_votes uq_patch_approval_votes_one_per_user; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_approval_votes
    ADD CONSTRAINT uq_patch_approval_votes_one_per_user UNIQUE (approval_id, user_id);


--
-- Name: patch_policies uq_patch_policies_slug; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_policies
    ADD CONSTRAINT uq_patch_policies_slug UNIQUE (slug);


--
-- Name: patch_policy_group_bindings uq_patch_policy_group_bindings_policy_group; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_policy_group_bindings
    ADD CONSTRAINT uq_patch_policy_group_bindings_policy_group UNIQUE (policy_id, group_id);


--
-- Name: patch_policy_host_bindings uq_patch_policy_host_bindings_policy_system; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_policy_host_bindings
    ADD CONSTRAINT uq_patch_policy_host_bindings_policy_system UNIQUE (policy_id, system_id);


--
-- Name: patch_policy_ring_bindings uq_patch_policy_ring_bindings_policy_ring; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_policy_ring_bindings
    ADD CONSTRAINT uq_patch_policy_ring_bindings_policy_ring UNIQUE (policy_id, ring_id);


--
-- Name: patch_policy_smart_group_bindings uq_patch_policy_smart_group_bindings_policy_smart_group; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_policy_smart_group_bindings
    ADD CONSTRAINT uq_patch_policy_smart_group_bindings_policy_smart_group UNIQUE (policy_id, smart_group_id);


--
-- Name: patch_ring_gate_definitions uq_patch_ring_gate_definitions_ring_signal_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_ring_gate_definitions
    ADD CONSTRAINT uq_patch_ring_gate_definitions_ring_signal_key UNIQUE (ring_id, signal_key);


--
-- Name: patch_ring_group_bindings uq_patch_ring_group_bindings_ring_group; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_ring_group_bindings
    ADD CONSTRAINT uq_patch_ring_group_bindings_ring_group UNIQUE (ring_id, group_id);


--
-- Name: patch_ring_host_bindings uq_patch_ring_host_bindings_ring_system; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_ring_host_bindings
    ADD CONSTRAINT uq_patch_ring_host_bindings_ring_system UNIQUE (ring_id, system_id);


--
-- Name: patch_ring_smart_group_bindings uq_patch_ring_smart_group_bindings_ring_smart_group; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_ring_smart_group_bindings
    ADD CONSTRAINT uq_patch_ring_smart_group_bindings_ring_smart_group UNIQUE (ring_id, smart_group_id);


--
-- Name: patch_rings uq_patch_rings_slug; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_rings
    ADD CONSTRAINT uq_patch_rings_slug UNIQUE (slug);


--
-- Name: patch_rings uq_patch_rings_sort_order; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_rings
    ADD CONSTRAINT uq_patch_rings_sort_order UNIQUE (sort_order);


--
-- Name: patch_rollback_dispatch_host_packages uq_patch_rollback_dispatch_host_packages_target; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_rollback_dispatch_host_packages
    ADD CONSTRAINT uq_patch_rollback_dispatch_host_packages_target UNIQUE (rollback_dispatch_host_id, package_name);


--
-- Name: patch_rollback_dispatch_hosts uq_patch_rollback_dispatch_hosts_target; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_rollback_dispatch_hosts
    ADD CONSTRAINT uq_patch_rollback_dispatch_hosts_target UNIQUE (rollback_dispatch_run_id, rollback_host_id);


--
-- Name: patch_update_execution_host_packages uq_patch_update_execution_host_packages_target; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_update_execution_host_packages
    ADD CONSTRAINT uq_patch_update_execution_host_packages_target UNIQUE (execution_host_id, package_name);


--
-- Name: patch_update_execution_hosts uq_patch_update_execution_hosts_target; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_update_execution_hosts
    ADD CONSTRAINT uq_patch_update_execution_hosts_target UNIQUE (execution_id, plan_host_id);


--
-- Name: patch_update_execution_reboots uq_patch_update_execution_reboots_target; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_update_execution_reboots
    ADD CONSTRAINT uq_patch_update_execution_reboots_target UNIQUE (execution_id, execution_host_id);


--
-- Name: patch_update_execution_rollback_approvals uq_patch_update_execution_rollback_approvals_target; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_update_execution_rollback_approvals
    ADD CONSTRAINT uq_patch_update_execution_rollback_approvals_target UNIQUE (rollback_id, approval_id);


--
-- Name: patch_update_execution_rollback_hosts uq_patch_update_execution_rollback_hosts_target; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_update_execution_rollback_hosts
    ADD CONSTRAINT uq_patch_update_execution_rollback_hosts_target UNIQUE (rollback_id, execution_host_id);


--
-- Name: patch_update_execution_rollback_packages uq_patch_update_execution_rollback_packages_target; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_update_execution_rollback_packages
    ADD CONSTRAINT uq_patch_update_execution_rollback_packages_target UNIQUE (rollback_host_id, package_name);


--
-- Name: patch_update_execution_rollbacks uq_patch_update_execution_rollbacks_execution; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_update_execution_rollbacks
    ADD CONSTRAINT uq_patch_update_execution_rollbacks_execution UNIQUE (execution_id);


--
-- Name: patch_update_plan_approvals uq_patch_update_plan_approvals_target; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_update_plan_approvals
    ADD CONSTRAINT uq_patch_update_plan_approvals_target UNIQUE (plan_id, approval_id);


--
-- Name: patch_update_plan_hosts uq_patch_update_plan_hosts_plan_system; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_update_plan_hosts
    ADD CONSTRAINT uq_patch_update_plan_hosts_plan_system UNIQUE (plan_id, system_id);


--
-- Name: patch_update_plan_preflight_snapshots uq_patch_update_plan_preflight_snapshots_target; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_update_plan_preflight_snapshots
    ADD CONSTRAINT uq_patch_update_plan_preflight_snapshots_target UNIQUE (plan_host_id, package_name);


--
-- Name: patch_update_plan_selected_packages uq_patch_update_plan_selected_packages_target; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_update_plan_selected_packages
    ADD CONSTRAINT uq_patch_update_plan_selected_packages_target UNIQUE (plan_host_id, package_name, advisory_id_snapshot);


--
-- Name: smart_group_memberships uq_smart_group_memberships_group_system; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.smart_group_memberships
    ADD CONSTRAINT uq_smart_group_memberships_group_system UNIQUE (smart_group_id, system_id);


--
-- Name: user user_email_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public."user"
    ADD CONSTRAINT user_email_key UNIQUE (email);


--
-- Name: user user_oidc_sub_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public."user"
    ADD CONSTRAINT user_oidc_sub_key UNIQUE (oidc_sub);


--
-- Name: user user_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public."user"
    ADD CONSTRAINT user_pkey PRIMARY KEY (id);


--
-- Name: user_role user_role_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_role
    ADD CONSTRAINT user_role_pkey PRIMARY KEY (user_id, role_id);


--
-- Name: user user_username_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public."user"
    ADD CONSTRAINT user_username_key UNIQUE (username);


--
-- Name: vault_config vault_config_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vault_config
    ADD CONSTRAINT vault_config_pkey PRIMARY KEY (id);


--
-- Name: ix_access_bindings_fleet_role_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_access_bindings_fleet_role_id ON public.access_bindings USING btree (fleet_role_id);


--
-- Name: ix_access_bindings_scope_group_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_access_bindings_scope_group_id ON public.access_bindings USING btree (scope_group_id);


--
-- Name: ix_access_bindings_scope_smart_group_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_access_bindings_scope_smart_group_id ON public.access_bindings USING btree (scope_smart_group_id);


--
-- Name: ix_access_bindings_subject_app_role_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_access_bindings_subject_app_role_id ON public.access_bindings USING btree (subject_app_role_id);


--
-- Name: ix_access_bindings_subject_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_access_bindings_subject_user_id ON public.access_bindings USING btree (subject_user_id);


--
-- Name: ix_access_grants_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_access_grants_expires_at ON public.access_grants USING btree (expires_at);


--
-- Name: ix_access_grants_fleet_role_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_access_grants_fleet_role_id ON public.access_grants USING btree (fleet_role_id);


--
-- Name: ix_access_grants_system_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_access_grants_system_id ON public.access_grants USING btree (system_id);


--
-- Name: ix_access_grants_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_access_grants_user_id ON public.access_grants USING btree (user_id);


--
-- Name: ix_access_grants_via_binding_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_access_grants_via_binding_id ON public.access_grants USING btree (via_binding_id);


--
-- Name: ix_access_requests_requested_by; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_access_requests_requested_by ON public.access_requests USING btree (requested_by);


--
-- Name: ix_access_requests_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_access_requests_status ON public.access_requests USING btree (status);


--
-- Name: ix_access_review_items_action; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_access_review_items_action ON public.access_review_items USING btree (action);


--
-- Name: ix_access_review_items_review_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_access_review_items_review_id ON public.access_review_items USING btree (review_id);


--
-- Name: ix_access_reviews_due_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_access_reviews_due_at ON public.access_reviews USING btree (due_at);


--
-- Name: ix_access_reviews_state; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_access_reviews_state ON public.access_reviews USING btree (state);


--
-- Name: ix_activation_redemptions_system_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_activation_redemptions_system_id ON public.activation_token_redemptions USING btree (system_id);


--
-- Name: ix_activation_tokens_default_group_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_activation_tokens_default_group_id ON public.activation_tokens USING btree (default_group_id);


--
-- Name: ix_activation_tokens_target_system_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_activation_tokens_target_system_id ON public.activation_tokens USING btree (target_system_id);


--
-- Name: ix_activation_tokens_token_prefix; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_activation_tokens_token_prefix ON public.activation_tokens USING btree (token_prefix);


--
-- Name: ix_airgap_bundles_status_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_airgap_bundles_status_created ON public.airgap_bundles USING btree (status, created_at);


--
-- Name: ix_alert_configs_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_alert_configs_id ON public.alert_configs USING btree (id);


--
-- Name: ix_alert_configs_scope_smart_group_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_alert_configs_scope_smart_group_id ON public.alert_configs USING btree (scope_smart_group_id);


--
-- Name: ix_alert_history_alert_config_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_alert_history_alert_config_id ON public.alert_history USING btree (alert_config_id);


--
-- Name: ix_alert_history_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_alert_history_id ON public.alert_history USING btree (id);


--
-- Name: ix_alert_history_next_retry_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_alert_history_next_retry_at ON public.alert_history USING btree (next_retry_at);


--
-- Name: ix_app_settings_setting_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ix_app_settings_setting_key ON public.app_settings USING btree (setting_key);


--
-- Name: ix_audit_events_action; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_audit_events_action ON public.audit_events USING btree (action);


--
-- Name: ix_audit_events_actor_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_audit_events_actor_user_id ON public.audit_events USING btree (actor_user_id);


--
-- Name: ix_audit_events_outcome; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_audit_events_outcome ON public.audit_events USING btree (outcome);


--
-- Name: ix_audit_events_target_system_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_audit_events_target_system_id ON public.audit_events USING btree (target_system_id);


--
-- Name: ix_audit_events_timestamp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_audit_events_timestamp ON public.audit_events USING btree ("timestamp");


--
-- Name: ix_audit_sink_deliveries_next_attempt; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_audit_sink_deliveries_next_attempt ON public.audit_sink_deliveries USING btree (next_attempt_at);


--
-- Name: ix_audit_sink_deliveries_sink_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_audit_sink_deliveries_sink_id ON public.audit_sink_deliveries USING btree (sink_id);


--
-- Name: ix_audit_sink_deliveries_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_audit_sink_deliveries_status ON public.audit_sink_deliveries USING btree (status);


--
-- Name: ix_baseline_checks_baseline_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_baseline_checks_baseline_id ON public.baseline_checks USING btree (baseline_id);


--
-- Name: ix_baseline_checks_run_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_baseline_checks_run_at ON public.baseline_checks USING btree (run_at);


--
-- Name: ix_baseline_checks_system_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_baseline_checks_system_id ON public.baseline_checks USING btree (system_id);


--
-- Name: ix_baselines_scope_smart_group_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_baselines_scope_smart_group_id ON public.baselines USING btree (scope_smart_group_id);


--
-- Name: ix_ca_rotations_performed_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_ca_rotations_performed_at ON public.ca_rotations USING btree (performed_at);


--
-- Name: ix_command_approval_votes_approval_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_command_approval_votes_approval_id ON public.command_approval_votes USING btree (approval_id);


--
-- Name: ix_command_approvals_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_command_approvals_expires_at ON public.command_approvals USING btree (expires_at);


--
-- Name: ix_command_distro_mapping_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_command_distro_mapping_id ON public.command_distro_mapping USING btree (id);


--
-- Name: ix_command_execution_metrics_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_command_execution_metrics_id ON public.command_execution_metrics USING btree (id);


--
-- Name: ix_command_execution_metrics_metric_date; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_command_execution_metrics_metric_date ON public.command_execution_metrics USING btree (metric_date);


--
-- Name: ix_command_execution_policies_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_command_execution_policies_id ON public.command_execution_policies USING btree (id);


--
-- Name: ix_command_execution_policies_name; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ix_command_execution_policies_name ON public.command_execution_policies USING btree (name);


--
-- Name: ix_command_execution_queue_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_command_execution_queue_id ON public.command_execution_queue USING btree (id);


--
-- Name: ix_command_execution_results_command_hash; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_command_execution_results_command_hash ON public.command_execution_results USING btree (command_hash);


--
-- Name: ix_command_execution_results_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_command_execution_results_id ON public.command_execution_results USING btree (id);


--
-- Name: ix_command_execution_system_policies_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_command_execution_system_policies_id ON public.command_execution_system_policies USING btree (id);


--
-- Name: ix_command_execution_user_policies_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_command_execution_user_policies_id ON public.command_execution_user_policies USING btree (id);


--
-- Name: ix_command_resource_limits_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_command_resource_limits_id ON public.command_resource_limits USING btree (id);


--
-- Name: ix_command_template_distros_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_command_template_distros_id ON public.command_template_distros USING btree (id);


--
-- Name: ix_command_templates_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_command_templates_id ON public.command_templates USING btree (id);


--
-- Name: ix_command_templates_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_command_templates_name ON public.command_templates USING btree (name);


--
-- Name: ix_command_validation_logs_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_command_validation_logs_id ON public.command_validation_logs USING btree (id);


--
-- Name: ix_command_validation_rules_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_command_validation_rules_id ON public.command_validation_rules USING btree (id);


--
-- Name: ix_command_validation_rules_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_command_validation_rules_name ON public.command_validation_rules USING btree (name);


--
-- Name: ix_command_whitelist_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_command_whitelist_id ON public.command_whitelist USING btree (id);


--
-- Name: ix_command_whitelist_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_command_whitelist_name ON public.command_whitelist USING btree (name);


--
-- Name: ix_compliance_policies_slug; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_compliance_policies_slug ON public.compliance_policies USING btree (slug);


--
-- Name: ix_compliance_policies_starter_pack_key; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_compliance_policies_starter_pack_key ON public.compliance_policies USING btree (starter_pack_key);


--
-- Name: ix_compliance_policy_checks_kind; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_compliance_policy_checks_kind ON public.compliance_policy_checks USING btree (kind);


--
-- Name: ix_compliance_policy_checks_policy; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_compliance_policy_checks_policy ON public.compliance_policy_checks USING btree (policy_id);


--
-- Name: ix_compliance_policy_evidence_check; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_compliance_policy_evidence_check ON public.compliance_policy_evidence USING btree (check_id);


--
-- Name: ix_compliance_policy_evidence_evaluated_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_compliance_policy_evidence_evaluated_at ON public.compliance_policy_evidence USING btree (evaluated_at);


--
-- Name: ix_compliance_policy_evidence_policy_evaluated_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_compliance_policy_evidence_policy_evaluated_at ON public.compliance_policy_evidence USING btree (policy_id, evaluated_at);


--
-- Name: ix_compliance_policy_evidence_run_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_compliance_policy_evidence_run_id ON public.compliance_policy_evidence USING btree (evaluation_run_id);


--
-- Name: ix_compliance_policy_evidence_system_evaluated_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_compliance_policy_evidence_system_evaluated_at ON public.compliance_policy_evidence USING btree (system_id, evaluated_at);


--
-- Name: ix_compliance_policy_evidence_verdict; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_compliance_policy_evidence_verdict ON public.compliance_policy_evidence USING btree (verdict);


--
-- Name: ix_compliance_remediation_execution_attempts_plan; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_compliance_remediation_execution_attempts_plan ON public.compliance_remediation_execution_attempts USING btree (plan_id);


--
-- Name: ix_compliance_remediation_execution_attempts_request; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_compliance_remediation_execution_attempts_request ON public.compliance_remediation_execution_attempts USING btree (request_id);


--
-- Name: ix_compliance_remediation_execution_attempts_state; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_compliance_remediation_execution_attempts_state ON public.compliance_remediation_execution_attempts USING btree (state);


--
-- Name: ix_compliance_remediation_execution_attempts_system; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_compliance_remediation_execution_attempts_system ON public.compliance_remediation_execution_attempts USING btree (system_id);


--
-- Name: ix_compliance_remediation_plans_plan_kind; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_compliance_remediation_plans_plan_kind ON public.compliance_remediation_plans USING btree (plan_kind);


--
-- Name: ix_compliance_remediation_plans_request; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_compliance_remediation_plans_request ON public.compliance_remediation_plans USING btree (request_id);


--
-- Name: ix_compliance_remediation_plans_state; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_compliance_remediation_plans_state ON public.compliance_remediation_plans USING btree (state);


--
-- Name: ix_compliance_remediation_plans_superseded_by; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_compliance_remediation_plans_superseded_by ON public.compliance_remediation_plans USING btree (superseded_by_plan_id);


--
-- Name: ix_compliance_remediation_requests_check; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_compliance_remediation_requests_check ON public.compliance_remediation_requests USING btree (check_id);


--
-- Name: ix_compliance_remediation_requests_evidence; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_compliance_remediation_requests_evidence ON public.compliance_remediation_requests USING btree (evidence_id);


--
-- Name: ix_compliance_remediation_requests_policy; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_compliance_remediation_requests_policy ON public.compliance_remediation_requests USING btree (policy_id);


--
-- Name: ix_compliance_remediation_requests_state; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_compliance_remediation_requests_state ON public.compliance_remediation_requests USING btree (state);


--
-- Name: ix_compliance_remediation_requests_system; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_compliance_remediation_requests_system ON public.compliance_remediation_requests USING btree (system_id);


--
-- Name: ix_content_channel_repos_mirror; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_content_channel_repos_mirror ON public.content_channel_repos USING btree (mirror_id);


--
-- Name: ix_content_profile_channels_channel; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_content_profile_channels_channel ON public.content_profile_channels USING btree (channel_id);


--
-- Name: ix_credentials_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_credentials_id ON public.credentials USING btree (id);


--
-- Name: ix_distro_lifecycle_distro_release; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_distro_lifecycle_distro_release ON public.distro_lifecycle USING btree (distro_id, release);


--
-- Name: ix_distro_lifecycle_override_scope; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_distro_lifecycle_override_scope ON public.distro_lifecycle_override USING btree (scope_type, scope_id, distro_id);


--
-- Name: ix_distros_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_distros_id ON public.distros USING btree (id);


--
-- Name: ix_distros_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_distros_name ON public.distros USING btree (name);


--
-- Name: ix_file_transfer_audits_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_file_transfer_audits_status ON public.file_transfer_audits USING btree (status);


--
-- Name: ix_file_transfer_audits_system_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_file_transfer_audits_system_id ON public.file_transfer_audits USING btree (system_id);


--
-- Name: ix_file_transfer_audits_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_file_transfer_audits_user_id ON public.file_transfer_audits USING btree (user_id);


--
-- Name: ix_fleet_operation_results_fleet_operation_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_fleet_operation_results_fleet_operation_id ON public.fleet_operation_results USING btree (fleet_operation_id);


--
-- Name: ix_fleet_operation_results_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_fleet_operation_results_id ON public.fleet_operation_results USING btree (id);


--
-- Name: ix_fleet_operations_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_fleet_operations_id ON public.fleet_operations USING btree (id);


--
-- Name: ix_fleet_operations_operation_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_fleet_operations_operation_type ON public.fleet_operations USING btree (operation_type);


--
-- Name: ix_fleet_roles_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_fleet_roles_id ON public.fleet_roles USING btree (id);


--
-- Name: ix_group_content_profile_subs_profile; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_group_content_profile_subs_profile ON public.group_content_profile_subscriptions USING btree (profile_id);


--
-- Name: ix_groups_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_groups_id ON public.groups USING btree (id);


--
-- Name: ix_groups_name; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ix_groups_name ON public.groups USING btree (name);


--
-- Name: ix_host_content_profile_subs_profile; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_host_content_profile_subs_profile ON public.host_content_profile_subscriptions USING btree (profile_id);


--
-- Name: ix_host_facts_distro_id_facts; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_host_facts_distro_id_facts ON public.host_facts USING btree (distro_id_facts);


--
-- Name: ix_host_facts_kernel_version; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_host_facts_kernel_version ON public.host_facts USING btree (kernel_version);


--
-- Name: ix_host_facts_reboot_required; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_host_facts_reboot_required ON public.host_facts USING btree (reboot_required);


--
-- Name: ix_host_facts_source_transport; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_host_facts_source_transport ON public.host_facts USING btree (source_transport);


--
-- Name: ix_host_mirror_serve_credentials_token_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_host_mirror_serve_credentials_token_id ON public.host_mirror_serve_credentials USING btree (token_id);


--
-- Name: ix_host_mirror_trust_mirror; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_host_mirror_trust_mirror ON public.host_mirror_trust USING btree (mirror_id);


--
-- Name: ix_host_user_states_system_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_host_user_states_system_id ON public.host_user_states USING btree (system_id);


--
-- Name: ix_job_history_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_job_history_id ON public.job_history USING btree (id);


--
-- Name: ix_jobs_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_jobs_id ON public.jobs USING btree (id);


--
-- Name: ix_maintenance_windows_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_maintenance_windows_id ON public.maintenance_windows USING btree (id);


--
-- Name: ix_mirror_signing_keys_repo_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_mirror_signing_keys_repo_status ON public.mirror_signing_keys USING btree (mirror_repo_id, status);


--
-- Name: ix_mirror_sync_run_packages_repo_name_version; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_mirror_sync_run_packages_repo_name_version ON public.mirror_sync_run_packages USING btree (mirror_repo_id, package_name, version);


--
-- Name: ix_mirror_sync_run_packages_run; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_mirror_sync_run_packages_run ON public.mirror_sync_run_packages USING btree (mirror_sync_run_id);


--
-- Name: ix_mirror_sync_runs_repo_started; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_mirror_sync_runs_repo_started ON public.mirror_sync_runs USING btree (mirror_repo_id, started_at);


--
-- Name: ix_notifications_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_notifications_created_at ON public.notifications USING btree (created_at);


--
-- Name: ix_notifications_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_notifications_id ON public.notifications USING btree (id);


--
-- Name: ix_notifications_is_read; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_notifications_is_read ON public.notifications USING btree (is_read);


--
-- Name: ix_notifications_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_notifications_user_id ON public.notifications USING btree (user_id);


--
-- Name: ix_oidc_login_state_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_oidc_login_state_expires_at ON public.oidc_login_state USING btree (expires_at);


--
-- Name: ix_oidc_login_state_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_oidc_login_state_id ON public.oidc_login_state USING btree (id);


--
-- Name: ix_oidc_login_state_state; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ix_oidc_login_state_state ON public.oidc_login_state USING btree (state);


--
-- Name: ix_oidc_provider_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_oidc_provider_id ON public.oidc_provider USING btree (id);


--
-- Name: ix_package_history_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_package_history_id ON public.package_history USING btree (id);


--
-- Name: ix_package_updates_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_package_updates_id ON public.package_updates USING btree (id);


--
-- Name: ix_packages_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_packages_id ON public.packages USING btree (id);


--
-- Name: ix_packages_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_packages_name ON public.packages USING btree (name);


--
-- Name: ix_patch_advisories_advisory_class; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_patch_advisories_advisory_class ON public.patch_advisories USING btree (advisory_class);


--
-- Name: ix_patch_advisories_distro_family; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_patch_advisories_distro_family ON public.patch_advisories USING btree (distro_family);


--
-- Name: ix_patch_advisories_source_kind_severity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_patch_advisories_source_kind_severity ON public.patch_advisories USING btree (source_kind, severity);


--
-- Name: ix_patch_advisory_fixed_packages_advisory; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_patch_advisory_fixed_packages_advisory ON public.patch_advisory_fixed_packages USING btree (advisory_id);


--
-- Name: ix_patch_advisory_fixed_packages_target; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_patch_advisory_fixed_packages_target ON public.patch_advisory_fixed_packages USING btree (distro_id, distro_release, package_name);


--
-- Name: ix_patch_advisory_host_applicability_advisory; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_patch_advisory_host_applicability_advisory ON public.patch_advisory_host_applicability USING btree (advisory_id);


--
-- Name: ix_patch_advisory_host_applicability_system_state; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_patch_advisory_host_applicability_system_state ON public.patch_advisory_host_applicability USING btree (system_id, state);


--
-- Name: ix_patch_advisory_imports_source_started; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_patch_advisory_imports_source_started ON public.patch_advisory_imports USING btree (source_kind, started_at DESC);


--
-- Name: ix_patch_approval_votes_approval_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_patch_approval_votes_approval_id ON public.patch_approval_votes USING btree (approval_id);


--
-- Name: ix_patch_approvals_pending_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_patch_approvals_pending_expires_at ON public.patch_approvals USING btree (expires_at) WHERE (((status)::text = 'pending'::text) AND (expires_at IS NOT NULL));


--
-- Name: ix_patch_approvals_subject; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_patch_approvals_subject ON public.patch_approvals USING btree (subject_kind, subject_id);


--
-- Name: ix_patch_policy_group_bindings_group; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_patch_policy_group_bindings_group ON public.patch_policy_group_bindings USING btree (group_id);


--
-- Name: ix_patch_policy_group_bindings_policy; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_patch_policy_group_bindings_policy ON public.patch_policy_group_bindings USING btree (policy_id);


--
-- Name: ix_patch_policy_host_bindings_policy; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_patch_policy_host_bindings_policy ON public.patch_policy_host_bindings USING btree (policy_id);


--
-- Name: ix_patch_policy_host_bindings_system; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_patch_policy_host_bindings_system ON public.patch_policy_host_bindings USING btree (system_id);


--
-- Name: ix_patch_policy_ring_bindings_policy; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_patch_policy_ring_bindings_policy ON public.patch_policy_ring_bindings USING btree (policy_id);


--
-- Name: ix_patch_policy_ring_bindings_ring; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_patch_policy_ring_bindings_ring ON public.patch_policy_ring_bindings USING btree (ring_id);


--
-- Name: ix_patch_policy_smart_group_bindings_policy; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_patch_policy_smart_group_bindings_policy ON public.patch_policy_smart_group_bindings USING btree (policy_id);


--
-- Name: ix_patch_policy_smart_group_bindings_smart_group; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_patch_policy_smart_group_bindings_smart_group ON public.patch_policy_smart_group_bindings USING btree (smart_group_id);


--
-- Name: ix_patch_ring_gate_definitions_ring; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_patch_ring_gate_definitions_ring ON public.patch_ring_gate_definitions USING btree (ring_id);


--
-- Name: ix_patch_ring_gate_definitions_ring_enabled; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_patch_ring_gate_definitions_ring_enabled ON public.patch_ring_gate_definitions USING btree (ring_id, enabled);


--
-- Name: ix_patch_ring_gate_signals_definition; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_patch_ring_gate_signals_definition ON public.patch_ring_gate_signals USING btree (gate_definition_id);


--
-- Name: ix_patch_ring_gate_signals_ring_signal_observed; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_patch_ring_gate_signals_ring_signal_observed ON public.patch_ring_gate_signals USING btree (ring_id, signal_key, observed_at DESC);


--
-- Name: ix_patch_ring_group_bindings_group; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_patch_ring_group_bindings_group ON public.patch_ring_group_bindings USING btree (group_id);


--
-- Name: ix_patch_ring_group_bindings_ring; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_patch_ring_group_bindings_ring ON public.patch_ring_group_bindings USING btree (ring_id);


--
-- Name: ix_patch_ring_host_bindings_ring; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_patch_ring_host_bindings_ring ON public.patch_ring_host_bindings USING btree (ring_id);


--
-- Name: ix_patch_ring_host_bindings_system; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_patch_ring_host_bindings_system ON public.patch_ring_host_bindings USING btree (system_id);


--
-- Name: ix_patch_ring_smart_group_bindings_ring; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_patch_ring_smart_group_bindings_ring ON public.patch_ring_smart_group_bindings USING btree (ring_id);


--
-- Name: ix_patch_ring_smart_group_bindings_smart_group; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_patch_ring_smart_group_bindings_smart_group ON public.patch_ring_smart_group_bindings USING btree (smart_group_id);


--
-- Name: ix_patch_rollback_dispatch_host_packages_host_outcome; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_patch_rollback_dispatch_host_packages_host_outcome ON public.patch_rollback_dispatch_host_packages USING btree (rollback_dispatch_host_id, outcome);


--
-- Name: ix_patch_rollback_dispatch_host_packages_rb_pkg; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_patch_rollback_dispatch_host_packages_rb_pkg ON public.patch_rollback_dispatch_host_packages USING btree (rollback_package_id);


--
-- Name: ix_patch_rollback_dispatch_hosts_rollback_host; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_patch_rollback_dispatch_hosts_rollback_host ON public.patch_rollback_dispatch_hosts USING btree (rollback_host_id);


--
-- Name: ix_patch_rollback_dispatch_hosts_run_state; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_patch_rollback_dispatch_hosts_run_state ON public.patch_rollback_dispatch_hosts USING btree (rollback_dispatch_run_id, state);


--
-- Name: ix_patch_rollback_dispatch_runs_approval_link; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_patch_rollback_dispatch_runs_approval_link ON public.patch_rollback_dispatch_runs USING btree (rollback_approval_link_id);


--
-- Name: ix_patch_rollback_dispatch_runs_rollback_state; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_patch_rollback_dispatch_runs_rollback_state ON public.patch_rollback_dispatch_runs USING btree (rollback_id, state);


--
-- Name: ix_patch_update_execution_host_packages_host_outcome; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_patch_update_execution_host_packages_host_outcome ON public.patch_update_execution_host_packages USING btree (execution_host_id, outcome);


--
-- Name: ix_patch_update_execution_host_packages_host_package; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_patch_update_execution_host_packages_host_package ON public.patch_update_execution_host_packages USING btree (execution_host_id, package_name);


--
-- Name: ix_patch_update_execution_hosts_execution_state; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_patch_update_execution_hosts_execution_state ON public.patch_update_execution_hosts USING btree (execution_id, state);


--
-- Name: ix_patch_update_execution_hosts_execution_wave; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_patch_update_execution_hosts_execution_wave ON public.patch_update_execution_hosts USING btree (execution_id, wave_index);


--
-- Name: ix_patch_update_execution_hosts_plan_host; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_patch_update_execution_hosts_plan_host ON public.patch_update_execution_hosts USING btree (plan_host_id);


--
-- Name: ix_patch_update_execution_reboots_execution_state; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_patch_update_execution_reboots_execution_state ON public.patch_update_execution_reboots USING btree (execution_id, state);


--
-- Name: ix_patch_update_execution_reboots_execution_wave; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_patch_update_execution_reboots_execution_wave ON public.patch_update_execution_reboots USING btree (execution_id, wave_index);


--
-- Name: ix_patch_update_execution_reboots_plan; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_patch_update_execution_reboots_plan ON public.patch_update_execution_reboots USING btree (plan_id_snapshot);


--
-- Name: ix_patch_update_execution_rollback_approvals_approval; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_patch_update_execution_rollback_approvals_approval ON public.patch_update_execution_rollback_approvals USING btree (approval_id);


--
-- Name: ix_patch_update_execution_rollback_approvals_rollback; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_patch_update_execution_rollback_approvals_rollback ON public.patch_update_execution_rollback_approvals USING btree (rollback_id);


--
-- Name: ix_patch_update_execution_rollback_hosts_execution_host; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_patch_update_execution_rollback_hosts_execution_host ON public.patch_update_execution_rollback_hosts USING btree (execution_host_id);


--
-- Name: ix_patch_update_execution_rollback_hosts_rollback_state; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_patch_update_execution_rollback_hosts_rollback_state ON public.patch_update_execution_rollback_hosts USING btree (rollback_id, state);


--
-- Name: ix_patch_update_execution_rollback_packages_exec_pkg; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_patch_update_execution_rollback_packages_exec_pkg ON public.patch_update_execution_rollback_packages USING btree (execution_host_package_id);


--
-- Name: ix_patch_update_execution_rollback_packages_host_state; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_patch_update_execution_rollback_packages_host_state ON public.patch_update_execution_rollback_packages USING btree (rollback_host_id, state);


--
-- Name: ix_patch_update_execution_rollbacks_plan; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_patch_update_execution_rollbacks_plan ON public.patch_update_execution_rollbacks USING btree (plan_id_snapshot);


--
-- Name: ix_patch_update_executions_plan_state; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_patch_update_executions_plan_state ON public.patch_update_executions USING btree (plan_id, state);


--
-- Name: ix_patch_update_plan_approvals_plan; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_patch_update_plan_approvals_plan ON public.patch_update_plan_approvals USING btree (plan_id);


--
-- Name: ix_patch_update_plan_hosts_plan_wave; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_patch_update_plan_hosts_plan_wave ON public.patch_update_plan_hosts USING btree (plan_id, wave_index);


--
-- Name: ix_patch_update_plan_hosts_state; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_patch_update_plan_hosts_state ON public.patch_update_plan_hosts USING btree (state);


--
-- Name: ix_patch_update_plan_hosts_system; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_patch_update_plan_hosts_system ON public.patch_update_plan_hosts USING btree (system_id);


--
-- Name: ix_patch_update_plan_preflight_snapshots_plan_host; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_patch_update_plan_preflight_snapshots_plan_host ON public.patch_update_plan_preflight_snapshots USING btree (plan_host_id);


--
-- Name: ix_patch_update_plan_preflight_snapshots_plan_host_state; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_patch_update_plan_preflight_snapshots_plan_host_state ON public.patch_update_plan_preflight_snapshots USING btree (plan_host_id, content_availability_state);


--
-- Name: ix_patch_update_plan_selected_packages_plan_host; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_patch_update_plan_selected_packages_plan_host ON public.patch_update_plan_selected_packages USING btree (plan_host_id);


--
-- Name: ix_patch_update_plan_selected_packages_plan_host_state; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_patch_update_plan_selected_packages_plan_host_state ON public.patch_update_plan_selected_packages USING btree (plan_host_id, state);


--
-- Name: ix_patch_update_plan_selected_packages_state; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_patch_update_plan_selected_packages_state ON public.patch_update_plan_selected_packages USING btree (state);


--
-- Name: ix_patch_update_plans_archived_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_patch_update_plans_archived_at ON public.patch_update_plans USING btree (archived_at);


--
-- Name: ix_patch_update_plans_policy; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_patch_update_plans_policy ON public.patch_update_plans USING btree (policy_id);


--
-- Name: ix_patch_update_plans_state; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_patch_update_plans_state ON public.patch_update_plans USING btree (state);


--
-- Name: ix_recordings_retention_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_recordings_retention_expires_at ON public.recordings USING btree (retention_expires_at);


--
-- Name: ix_recordings_session_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_recordings_session_id ON public.recordings USING btree (session_id);


--
-- Name: ix_recordings_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_recordings_user_id ON public.recordings USING btree (user_id);


--
-- Name: ix_refresh_tokens_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_refresh_tokens_id ON public.refresh_tokens USING btree (id);


--
-- Name: ix_refresh_tokens_token; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ix_refresh_tokens_token ON public.refresh_tokens USING btree (token);


--
-- Name: ix_repo_sources_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_repo_sources_id ON public.repo_sources USING btree (id);


--
-- Name: ix_report_runs_kind_started_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_report_runs_kind_started_at ON public.report_runs USING btree (report_kind, started_at);


--
-- Name: ix_report_runs_state; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_report_runs_state ON public.report_runs USING btree (state);


--
-- Name: ix_report_runs_triggered_by; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_report_runs_triggered_by ON public.report_runs USING btree (triggered_by);


--
-- Name: ix_report_schedules_enabled; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_report_schedules_enabled ON public.report_schedules USING btree (enabled);


--
-- Name: ix_report_schedules_next_run_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_report_schedules_next_run_at ON public.report_schedules USING btree (next_run_at);


--
-- Name: ix_report_schedules_report_kind; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_report_schedules_report_kind ON public.report_schedules USING btree (report_kind);


--
-- Name: ix_revocation_work_next_retry_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_revocation_work_next_retry_at ON public.revocation_work USING btree (next_retry_at);


--
-- Name: ix_revocation_work_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_revocation_work_status ON public.revocation_work USING btree (status);


--
-- Name: ix_revocation_work_system_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_revocation_work_system_id ON public.revocation_work USING btree (system_id);


--
-- Name: ix_revocation_work_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_revocation_work_user_id ON public.revocation_work USING btree (user_id);


--
-- Name: ix_role_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_role_id ON public.role USING btree (id);


--
-- Name: ix_saved_views_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_saved_views_id ON public.saved_views USING btree (id);


--
-- Name: ix_saved_views_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_saved_views_user_id ON public.saved_views USING btree (user_id);


--
-- Name: ix_session_approvals_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_session_approvals_expires_at ON public.session_approvals USING btree (expires_at);


--
-- Name: ix_session_approvals_requester_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_session_approvals_requester_id ON public.session_approvals USING btree (requester_id);


--
-- Name: ix_session_approvals_state; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_session_approvals_state ON public.session_approvals USING btree (state);


--
-- Name: ix_session_locks_released_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_session_locks_released_at ON public.session_locks USING btree (released_at);


--
-- Name: ix_session_locks_subject_app_role_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_session_locks_subject_app_role_id ON public.session_locks USING btree (subject_app_role_id);


--
-- Name: ix_session_locks_subject_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_session_locks_subject_user_id ON public.session_locks USING btree (subject_user_id);


--
-- Name: ix_sessions_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sessions_status ON public.sessions USING btree (status);


--
-- Name: ix_sessions_system_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sessions_system_id ON public.sessions USING btree (system_id);


--
-- Name: ix_sessions_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_sessions_user_id ON public.sessions USING btree (user_id);


--
-- Name: ix_smart_group_content_profile_subs_profile; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_smart_group_content_profile_subs_profile ON public.smart_group_content_profile_subscriptions USING btree (profile_id);


--
-- Name: ix_smart_group_memberships_smart_group_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_smart_group_memberships_smart_group_id ON public.smart_group_memberships USING btree (smart_group_id);


--
-- Name: ix_smart_group_memberships_system_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_smart_group_memberships_system_id ON public.smart_group_memberships USING btree (system_id);


--
-- Name: ix_smart_groups_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_smart_groups_id ON public.smart_groups USING btree (id);


--
-- Name: ix_ssh_host_keys_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_ssh_host_keys_id ON public.ssh_host_keys USING btree (id);


--
-- Name: ix_ssh_security_logs_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_ssh_security_logs_id ON public.ssh_security_logs USING btree (id);


--
-- Name: ix_ssh_security_policies_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_ssh_security_policies_id ON public.ssh_security_policies USING btree (id);


--
-- Name: ix_system_audits_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_system_audits_id ON public.system_audits USING btree (id);


--
-- Name: ix_system_metadata_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_system_metadata_id ON public.system_metadata USING btree (id);


--
-- Name: ix_systems_agent_cert_serial; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ix_systems_agent_cert_serial ON public.systems USING btree (agent_cert_serial);


--
-- Name: ix_systems_distro_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_systems_distro_id ON public.systems USING btree (distro_id);


--
-- Name: ix_systems_hostname; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ix_systems_hostname ON public.systems USING btree (hostname);


--
-- Name: ix_systems_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_systems_id ON public.systems USING btree (id);


--
-- Name: ix_systems_os_version; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_systems_os_version ON public.systems USING btree (os_version);


--
-- Name: ix_tags_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_tags_id ON public.tags USING btree (id);


--
-- Name: ix_tags_name; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ix_tags_name ON public.tags USING btree (name);


--
-- Name: ix_totp_challenges_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_totp_challenges_expires_at ON public.totp_challenges USING btree (expires_at);


--
-- Name: ix_totp_challenges_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_totp_challenges_user_id ON public.totp_challenges USING btree (user_id);


--
-- Name: ix_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_user_id ON public."user" USING btree (id);


--
-- Name: ix_vault_config_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_vault_config_id ON public.vault_config USING btree (id);


--
-- Name: uq_airgap_bundle_signing_keys_one_active; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_airgap_bundle_signing_keys_one_active ON public.airgap_bundle_signing_keys USING btree (status) WHERE ((status)::text = 'active'::text);


--
-- Name: uq_airgap_import_trust_keys_active_fingerprint; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_airgap_import_trust_keys_active_fingerprint ON public.airgap_import_trust_keys USING btree (gpg_fingerprint) WHERE (deleted_at IS NULL);


--
-- Name: uq_compliance_policies_starter_pack_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_compliance_policies_starter_pack_key ON public.compliance_policies USING btree (starter_pack_key) WHERE (starter_pack_key IS NOT NULL);


--
-- Name: uq_compliance_remediation_plans_current; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_compliance_remediation_plans_current ON public.compliance_remediation_plans USING btree (request_id) WHERE (superseded_by_plan_id IS NULL);


--
-- Name: uq_mirror_signing_keys_one_active_per_mirror; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_mirror_signing_keys_one_active_per_mirror ON public.mirror_signing_keys USING btree (mirror_repo_id) WHERE ((status)::text = 'active'::text);


--
-- Name: uq_mirror_signing_keys_one_pending_per_mirror; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_mirror_signing_keys_one_pending_per_mirror ON public.mirror_signing_keys USING btree (mirror_repo_id) WHERE ((status)::text = 'pending_cutover'::text);


--
-- Name: uq_mirror_sync_run_packages_no_arch; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_mirror_sync_run_packages_no_arch ON public.mirror_sync_run_packages USING btree (mirror_sync_run_id, package_name, version) WHERE (arch IS NULL);


--
-- Name: uq_patch_policies_single_fleet_default; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_patch_policies_single_fleet_default ON public.patch_policies USING btree (is_fleet_default) WHERE (is_fleet_default = true);


--
-- Name: uq_patch_rollback_dispatch_runs_rollback_active; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_patch_rollback_dispatch_runs_rollback_active ON public.patch_rollback_dispatch_runs USING btree (rollback_id) WHERE ((state)::text = ANY ((ARRAY['pending'::character varying, 'running'::character varying, 'paused'::character varying])::text[]));


--
-- Name: uq_patch_update_executions_plan_active; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_patch_update_executions_plan_active ON public.patch_update_executions USING btree (plan_id) WHERE ((state)::text = ANY ((ARRAY['pending'::character varying, 'running'::character varying, 'paused'::character varying])::text[]));


--
-- Name: uq_patch_update_plan_selected_packages_no_advisory; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_patch_update_plan_selected_packages_no_advisory ON public.patch_update_plan_selected_packages USING btree (plan_host_id, package_name) WHERE (advisory_id_snapshot IS NULL);


--
-- Name: ux_content_channel_repos_inherit_suite; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ux_content_channel_repos_inherit_suite ON public.content_channel_repos USING btree (channel_id, mirror_id) WHERE (suite_override IS NULL);


--
-- Name: access_bindings access_bindings_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.access_bindings
    ADD CONSTRAINT access_bindings_created_by_fkey FOREIGN KEY (created_by) REFERENCES public."user"(id);


--
-- Name: access_bindings access_bindings_fleet_role_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.access_bindings
    ADD CONSTRAINT access_bindings_fleet_role_id_fkey FOREIGN KEY (fleet_role_id) REFERENCES public.fleet_roles(id) ON DELETE RESTRICT;


--
-- Name: access_bindings access_bindings_scope_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.access_bindings
    ADD CONSTRAINT access_bindings_scope_group_id_fkey FOREIGN KEY (scope_group_id) REFERENCES public.groups(id) ON DELETE CASCADE;


--
-- Name: access_bindings access_bindings_scope_smart_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.access_bindings
    ADD CONSTRAINT access_bindings_scope_smart_group_id_fkey FOREIGN KEY (scope_smart_group_id) REFERENCES public.smart_groups(id) ON DELETE CASCADE;


--
-- Name: access_bindings access_bindings_subject_app_role_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.access_bindings
    ADD CONSTRAINT access_bindings_subject_app_role_id_fkey FOREIGN KEY (subject_app_role_id) REFERENCES public.role(id) ON DELETE CASCADE;


--
-- Name: access_bindings access_bindings_subject_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.access_bindings
    ADD CONSTRAINT access_bindings_subject_user_id_fkey FOREIGN KEY (subject_user_id) REFERENCES public."user"(id) ON DELETE CASCADE;


--
-- Name: access_grants access_grants_fleet_role_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.access_grants
    ADD CONSTRAINT access_grants_fleet_role_id_fkey FOREIGN KEY (fleet_role_id) REFERENCES public.fleet_roles(id) ON DELETE CASCADE;


--
-- Name: access_grants access_grants_system_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.access_grants
    ADD CONSTRAINT access_grants_system_id_fkey FOREIGN KEY (system_id) REFERENCES public.systems(id) ON DELETE CASCADE;


--
-- Name: access_grants access_grants_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.access_grants
    ADD CONSTRAINT access_grants_user_id_fkey FOREIGN KEY (user_id) REFERENCES public."user"(id) ON DELETE CASCADE;


--
-- Name: access_grants access_grants_via_binding_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.access_grants
    ADD CONSTRAINT access_grants_via_binding_id_fkey FOREIGN KEY (via_binding_id) REFERENCES public.access_bindings(id) ON DELETE CASCADE;


--
-- Name: access_requests access_requests_decided_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.access_requests
    ADD CONSTRAINT access_requests_decided_by_fkey FOREIGN KEY (decided_by) REFERENCES public."user"(id) ON DELETE SET NULL;


--
-- Name: access_requests access_requests_fleet_role_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.access_requests
    ADD CONSTRAINT access_requests_fleet_role_id_fkey FOREIGN KEY (fleet_role_id) REFERENCES public.fleet_roles(id) ON DELETE CASCADE;


--
-- Name: access_requests access_requests_requested_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.access_requests
    ADD CONSTRAINT access_requests_requested_by_fkey FOREIGN KEY (requested_by) REFERENCES public."user"(id) ON DELETE CASCADE;


--
-- Name: access_requests access_requests_resulting_binding_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.access_requests
    ADD CONSTRAINT access_requests_resulting_binding_id_fkey FOREIGN KEY (resulting_binding_id) REFERENCES public.access_bindings(id) ON DELETE SET NULL;


--
-- Name: access_requests access_requests_scope_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.access_requests
    ADD CONSTRAINT access_requests_scope_group_id_fkey FOREIGN KEY (scope_group_id) REFERENCES public.groups(id) ON DELETE CASCADE;


--
-- Name: access_requests access_requests_scope_smart_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.access_requests
    ADD CONSTRAINT access_requests_scope_smart_group_id_fkey FOREIGN KEY (scope_smart_group_id) REFERENCES public.smart_groups(id) ON DELETE CASCADE;


--
-- Name: access_review_items access_review_items_binding_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.access_review_items
    ADD CONSTRAINT access_review_items_binding_id_fkey FOREIGN KEY (binding_id) REFERENCES public.access_bindings(id) ON DELETE SET NULL;


--
-- Name: access_review_items access_review_items_decided_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.access_review_items
    ADD CONSTRAINT access_review_items_decided_by_fkey FOREIGN KEY (decided_by) REFERENCES public."user"(id) ON DELETE SET NULL;


--
-- Name: access_review_items access_review_items_review_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.access_review_items
    ADD CONSTRAINT access_review_items_review_id_fkey FOREIGN KEY (review_id) REFERENCES public.access_reviews(id) ON DELETE CASCADE;


--
-- Name: access_reviews access_reviews_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.access_reviews
    ADD CONSTRAINT access_reviews_created_by_fkey FOREIGN KEY (created_by) REFERENCES public."user"(id) ON DELETE SET NULL;


--
-- Name: access_reviews access_reviews_reviewer_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.access_reviews
    ADD CONSTRAINT access_reviews_reviewer_id_fkey FOREIGN KEY (reviewer_id) REFERENCES public."user"(id) ON DELETE SET NULL;


--
-- Name: activation_token_redemptions activation_token_redemptions_activation_token_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.activation_token_redemptions
    ADD CONSTRAINT activation_token_redemptions_activation_token_id_fkey FOREIGN KEY (activation_token_id) REFERENCES public.activation_tokens(id) ON DELETE CASCADE;


--
-- Name: activation_token_redemptions activation_token_redemptions_system_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.activation_token_redemptions
    ADD CONSTRAINT activation_token_redemptions_system_id_fkey FOREIGN KEY (system_id) REFERENCES public.systems(id) ON DELETE SET NULL;


--
-- Name: activation_tokens activation_tokens_created_by_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.activation_tokens
    ADD CONSTRAINT activation_tokens_created_by_user_id_fkey FOREIGN KEY (created_by_user_id) REFERENCES public."user"(id) ON DELETE RESTRICT;


--
-- Name: activation_tokens activation_tokens_default_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.activation_tokens
    ADD CONSTRAINT activation_tokens_default_group_id_fkey FOREIGN KEY (default_group_id) REFERENCES public.groups(id) ON DELETE RESTRICT;


--
-- Name: activation_tokens activation_tokens_revoked_by_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.activation_tokens
    ADD CONSTRAINT activation_tokens_revoked_by_user_id_fkey FOREIGN KEY (revoked_by_user_id) REFERENCES public."user"(id) ON DELETE SET NULL;


--
-- Name: activation_tokens activation_tokens_target_system_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.activation_tokens
    ADD CONSTRAINT activation_tokens_target_system_id_fkey FOREIGN KEY (target_system_id) REFERENCES public.systems(id) ON DELETE RESTRICT;


--
-- Name: airgap_bundles airgap_bundles_signing_key_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.airgap_bundles
    ADD CONSTRAINT airgap_bundles_signing_key_id_fkey FOREIGN KEY (signing_key_id) REFERENCES public.airgap_bundle_signing_keys(id) ON DELETE SET NULL;


--
-- Name: alert_configs alert_configs_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alert_configs
    ADD CONSTRAINT alert_configs_created_by_fkey FOREIGN KEY (created_by) REFERENCES public."user"(id);


--
-- Name: alert_configs alert_configs_scope_smart_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alert_configs
    ADD CONSTRAINT alert_configs_scope_smart_group_id_fkey FOREIGN KEY (scope_smart_group_id) REFERENCES public.smart_groups(id) ON DELETE SET NULL;


--
-- Name: alert_history alert_history_alert_config_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alert_history
    ADD CONSTRAINT alert_history_alert_config_id_fkey FOREIGN KEY (alert_config_id) REFERENCES public.alert_configs(id) ON DELETE CASCADE;


--
-- Name: audit_events audit_events_actor_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_events
    ADD CONSTRAINT audit_events_actor_user_id_fkey FOREIGN KEY (actor_user_id) REFERENCES public."user"(id) ON DELETE SET NULL;


--
-- Name: audit_events audit_events_target_system_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_events
    ADD CONSTRAINT audit_events_target_system_id_fkey FOREIGN KEY (target_system_id) REFERENCES public.systems(id) ON DELETE SET NULL;


--
-- Name: audit_sink_deliveries audit_sink_deliveries_event_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_sink_deliveries
    ADD CONSTRAINT audit_sink_deliveries_event_id_fkey FOREIGN KEY (event_id) REFERENCES public.audit_events(id) ON DELETE CASCADE;


--
-- Name: audit_sink_deliveries audit_sink_deliveries_sink_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_sink_deliveries
    ADD CONSTRAINT audit_sink_deliveries_sink_id_fkey FOREIGN KEY (sink_id) REFERENCES public.audit_sinks(id) ON DELETE CASCADE;


--
-- Name: baseline_checks baseline_checks_baseline_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.baseline_checks
    ADD CONSTRAINT baseline_checks_baseline_id_fkey FOREIGN KEY (baseline_id) REFERENCES public.baselines(id) ON DELETE CASCADE;


--
-- Name: baseline_checks baseline_checks_system_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.baseline_checks
    ADD CONSTRAINT baseline_checks_system_id_fkey FOREIGN KEY (system_id) REFERENCES public.systems(id) ON DELETE CASCADE;


--
-- Name: baselines baselines_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.baselines
    ADD CONSTRAINT baselines_created_by_fkey FOREIGN KEY (created_by) REFERENCES public."user"(id);


--
-- Name: baselines baselines_scope_smart_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.baselines
    ADD CONSTRAINT baselines_scope_smart_group_id_fkey FOREIGN KEY (scope_smart_group_id) REFERENCES public.smart_groups(id) ON DELETE SET NULL;


--
-- Name: ca_rotations ca_rotations_performed_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ca_rotations
    ADD CONSTRAINT ca_rotations_performed_by_fkey FOREIGN KEY (performed_by) REFERENCES public."user"(id);


--
-- Name: command_approval_votes command_approval_votes_approval_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.command_approval_votes
    ADD CONSTRAINT command_approval_votes_approval_id_fkey FOREIGN KEY (approval_id) REFERENCES public.command_approvals(id) ON DELETE CASCADE;


--
-- Name: command_approval_votes command_approval_votes_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.command_approval_votes
    ADD CONSTRAINT command_approval_votes_user_id_fkey FOREIGN KEY (user_id) REFERENCES public."user"(id);


--
-- Name: command_approvals command_approvals_decided_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.command_approvals
    ADD CONSTRAINT command_approvals_decided_by_fkey FOREIGN KEY (decided_by) REFERENCES public."user"(id);


--
-- Name: command_approvals command_approvals_requested_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.command_approvals
    ADD CONSTRAINT command_approvals_requested_by_fkey FOREIGN KEY (requested_by) REFERENCES public."user"(id);


--
-- Name: command_approvals command_approvals_system_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.command_approvals
    ADD CONSTRAINT command_approvals_system_id_fkey FOREIGN KEY (system_id) REFERENCES public.systems(id) ON DELETE CASCADE;


--
-- Name: command_approvals command_approvals_whitelist_entry_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.command_approvals
    ADD CONSTRAINT command_approvals_whitelist_entry_id_fkey FOREIGN KEY (whitelist_entry_id) REFERENCES public.command_whitelist(id) ON DELETE SET NULL;


--
-- Name: command_distro_mapping command_distro_mapping_command_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.command_distro_mapping
    ADD CONSTRAINT command_distro_mapping_command_id_fkey FOREIGN KEY (command_id) REFERENCES public.command_whitelist(id);


--
-- Name: command_distro_mapping command_distro_mapping_distro_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.command_distro_mapping
    ADD CONSTRAINT command_distro_mapping_distro_id_fkey FOREIGN KEY (distro_id) REFERENCES public.distros(id);


--
-- Name: command_execution_metrics command_execution_metrics_system_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.command_execution_metrics
    ADD CONSTRAINT command_execution_metrics_system_id_fkey FOREIGN KEY (system_id) REFERENCES public.systems(id);


--
-- Name: command_execution_metrics command_execution_metrics_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.command_execution_metrics
    ADD CONSTRAINT command_execution_metrics_user_id_fkey FOREIGN KEY (user_id) REFERENCES public."user"(id);


--
-- Name: command_execution_policies command_execution_policies_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.command_execution_policies
    ADD CONSTRAINT command_execution_policies_created_by_fkey FOREIGN KEY (created_by) REFERENCES public."user"(id);


--
-- Name: command_execution_queue command_execution_queue_execution_result_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.command_execution_queue
    ADD CONSTRAINT command_execution_queue_execution_result_id_fkey FOREIGN KEY (execution_result_id) REFERENCES public.command_execution_results(id);


--
-- Name: command_execution_queue command_execution_queue_system_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.command_execution_queue
    ADD CONSTRAINT command_execution_queue_system_id_fkey FOREIGN KEY (system_id) REFERENCES public.systems(id);


--
-- Name: command_execution_queue command_execution_queue_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.command_execution_queue
    ADD CONSTRAINT command_execution_queue_user_id_fkey FOREIGN KEY (user_id) REFERENCES public."user"(id);


--
-- Name: command_execution_results command_execution_results_system_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.command_execution_results
    ADD CONSTRAINT command_execution_results_system_id_fkey FOREIGN KEY (system_id) REFERENCES public.systems(id);


--
-- Name: command_execution_results command_execution_results_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.command_execution_results
    ADD CONSTRAINT command_execution_results_user_id_fkey FOREIGN KEY (user_id) REFERENCES public."user"(id);


--
-- Name: command_execution_system_policies command_execution_system_policies_policy_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.command_execution_system_policies
    ADD CONSTRAINT command_execution_system_policies_policy_id_fkey FOREIGN KEY (policy_id) REFERENCES public.command_execution_policies(id);


--
-- Name: command_execution_system_policies command_execution_system_policies_system_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.command_execution_system_policies
    ADD CONSTRAINT command_execution_system_policies_system_id_fkey FOREIGN KEY (system_id) REFERENCES public.systems(id);


--
-- Name: command_execution_user_policies command_execution_user_policies_policy_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.command_execution_user_policies
    ADD CONSTRAINT command_execution_user_policies_policy_id_fkey FOREIGN KEY (policy_id) REFERENCES public.command_execution_policies(id);


--
-- Name: command_execution_user_policies command_execution_user_policies_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.command_execution_user_policies
    ADD CONSTRAINT command_execution_user_policies_user_id_fkey FOREIGN KEY (user_id) REFERENCES public."user"(id);


--
-- Name: command_resource_limits command_resource_limits_execution_result_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.command_resource_limits
    ADD CONSTRAINT command_resource_limits_execution_result_id_fkey FOREIGN KEY (execution_result_id) REFERENCES public.command_execution_results(id);


--
-- Name: command_template_distros command_template_distros_distro_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.command_template_distros
    ADD CONSTRAINT command_template_distros_distro_id_fkey FOREIGN KEY (distro_id) REFERENCES public.distros(id);


--
-- Name: command_template_distros command_template_distros_template_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.command_template_distros
    ADD CONSTRAINT command_template_distros_template_id_fkey FOREIGN KEY (template_id) REFERENCES public.command_templates(id);


--
-- Name: command_templates command_templates_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.command_templates
    ADD CONSTRAINT command_templates_created_by_fkey FOREIGN KEY (created_by) REFERENCES public."user"(id);


--
-- Name: command_validation_logs command_validation_logs_command_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.command_validation_logs
    ADD CONSTRAINT command_validation_logs_command_id_fkey FOREIGN KEY (command_id) REFERENCES public.command_whitelist(id);


--
-- Name: command_validation_logs command_validation_logs_system_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.command_validation_logs
    ADD CONSTRAINT command_validation_logs_system_id_fkey FOREIGN KEY (system_id) REFERENCES public.systems(id);


--
-- Name: command_validation_logs command_validation_logs_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.command_validation_logs
    ADD CONSTRAINT command_validation_logs_user_id_fkey FOREIGN KEY (user_id) REFERENCES public."user"(id);


--
-- Name: command_validation_logs command_validation_logs_validation_rule_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.command_validation_logs
    ADD CONSTRAINT command_validation_logs_validation_rule_id_fkey FOREIGN KEY (validation_rule_id) REFERENCES public.command_validation_rules(id);


--
-- Name: command_validation_rules command_validation_rules_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.command_validation_rules
    ADD CONSTRAINT command_validation_rules_created_by_fkey FOREIGN KEY (created_by) REFERENCES public."user"(id);


--
-- Name: command_whitelist command_whitelist_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.command_whitelist
    ADD CONSTRAINT command_whitelist_created_by_fkey FOREIGN KEY (created_by) REFERENCES public."user"(id);


--
-- Name: compliance_policies compliance_policies_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.compliance_policies
    ADD CONSTRAINT compliance_policies_created_by_fkey FOREIGN KEY (created_by) REFERENCES public."user"(id);


--
-- Name: compliance_policy_checks compliance_policy_checks_policy_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.compliance_policy_checks
    ADD CONSTRAINT compliance_policy_checks_policy_id_fkey FOREIGN KEY (policy_id) REFERENCES public.compliance_policies(id) ON DELETE CASCADE;


--
-- Name: compliance_policy_evidence compliance_policy_evidence_check_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.compliance_policy_evidence
    ADD CONSTRAINT compliance_policy_evidence_check_id_fkey FOREIGN KEY (check_id) REFERENCES public.compliance_policy_checks(id) ON DELETE SET NULL;


--
-- Name: compliance_policy_evidence compliance_policy_evidence_policy_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.compliance_policy_evidence
    ADD CONSTRAINT compliance_policy_evidence_policy_id_fkey FOREIGN KEY (policy_id) REFERENCES public.compliance_policies(id) ON DELETE CASCADE;


--
-- Name: compliance_policy_evidence compliance_policy_evidence_system_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.compliance_policy_evidence
    ADD CONSTRAINT compliance_policy_evidence_system_id_fkey FOREIGN KEY (system_id) REFERENCES public.systems(id) ON DELETE CASCADE;


--
-- Name: compliance_remediation_execution_attempts compliance_remediation_execution_attem_approval_decided_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.compliance_remediation_execution_attempts
    ADD CONSTRAINT compliance_remediation_execution_attem_approval_decided_by_fkey FOREIGN KEY (approval_decided_by) REFERENCES public."user"(id) ON DELETE SET NULL;


--
-- Name: compliance_remediation_execution_attempts compliance_remediation_execution_attempts_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.compliance_remediation_execution_attempts
    ADD CONSTRAINT compliance_remediation_execution_attempts_created_by_fkey FOREIGN KEY (created_by) REFERENCES public."user"(id);


--
-- Name: compliance_remediation_execution_attempts compliance_remediation_execution_attempts_plan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.compliance_remediation_execution_attempts
    ADD CONSTRAINT compliance_remediation_execution_attempts_plan_id_fkey FOREIGN KEY (plan_id) REFERENCES public.compliance_remediation_plans(id) ON DELETE SET NULL;


--
-- Name: compliance_remediation_execution_attempts compliance_remediation_execution_attempts_request_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.compliance_remediation_execution_attempts
    ADD CONSTRAINT compliance_remediation_execution_attempts_request_id_fkey FOREIGN KEY (request_id) REFERENCES public.compliance_remediation_requests(id) ON DELETE CASCADE;


--
-- Name: compliance_remediation_execution_attempts compliance_remediation_execution_attempts_system_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.compliance_remediation_execution_attempts
    ADD CONSTRAINT compliance_remediation_execution_attempts_system_id_fkey FOREIGN KEY (system_id) REFERENCES public.systems(id) ON DELETE CASCADE;


--
-- Name: compliance_remediation_plans compliance_remediation_plans_acknowledged_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.compliance_remediation_plans
    ADD CONSTRAINT compliance_remediation_plans_acknowledged_by_fkey FOREIGN KEY (acknowledged_by) REFERENCES public."user"(id);


--
-- Name: compliance_remediation_plans compliance_remediation_plans_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.compliance_remediation_plans
    ADD CONSTRAINT compliance_remediation_plans_created_by_fkey FOREIGN KEY (created_by) REFERENCES public."user"(id);


--
-- Name: compliance_remediation_plans compliance_remediation_plans_request_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.compliance_remediation_plans
    ADD CONSTRAINT compliance_remediation_plans_request_id_fkey FOREIGN KEY (request_id) REFERENCES public.compliance_remediation_requests(id) ON DELETE CASCADE;


--
-- Name: compliance_remediation_plans compliance_remediation_plans_superseded_by_plan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.compliance_remediation_plans
    ADD CONSTRAINT compliance_remediation_plans_superseded_by_plan_id_fkey FOREIGN KEY (superseded_by_plan_id) REFERENCES public.compliance_remediation_plans(id) ON DELETE SET NULL;


--
-- Name: compliance_remediation_requests compliance_remediation_requests_check_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.compliance_remediation_requests
    ADD CONSTRAINT compliance_remediation_requests_check_id_fkey FOREIGN KEY (check_id) REFERENCES public.compliance_policy_checks(id) ON DELETE SET NULL;


--
-- Name: compliance_remediation_requests compliance_remediation_requests_decided_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.compliance_remediation_requests
    ADD CONSTRAINT compliance_remediation_requests_decided_by_fkey FOREIGN KEY (decided_by) REFERENCES public."user"(id);


--
-- Name: compliance_remediation_requests compliance_remediation_requests_evidence_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.compliance_remediation_requests
    ADD CONSTRAINT compliance_remediation_requests_evidence_id_fkey FOREIGN KEY (evidence_id) REFERENCES public.compliance_policy_evidence(id) ON DELETE SET NULL;


--
-- Name: compliance_remediation_requests compliance_remediation_requests_policy_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.compliance_remediation_requests
    ADD CONSTRAINT compliance_remediation_requests_policy_id_fkey FOREIGN KEY (policy_id) REFERENCES public.compliance_policies(id) ON DELETE CASCADE;


--
-- Name: compliance_remediation_requests compliance_remediation_requests_requested_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.compliance_remediation_requests
    ADD CONSTRAINT compliance_remediation_requests_requested_by_fkey FOREIGN KEY (requested_by) REFERENCES public."user"(id);


--
-- Name: compliance_remediation_requests compliance_remediation_requests_system_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.compliance_remediation_requests
    ADD CONSTRAINT compliance_remediation_requests_system_id_fkey FOREIGN KEY (system_id) REFERENCES public.systems(id) ON DELETE CASCADE;


--
-- Name: content_channel_repos content_channel_repos_channel_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.content_channel_repos
    ADD CONSTRAINT content_channel_repos_channel_id_fkey FOREIGN KEY (channel_id) REFERENCES public.content_channels(id) ON DELETE CASCADE;


--
-- Name: content_channel_repos content_channel_repos_mirror_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.content_channel_repos
    ADD CONSTRAINT content_channel_repos_mirror_id_fkey FOREIGN KEY (mirror_id) REFERENCES public.mirror_repos(id) ON DELETE CASCADE;


--
-- Name: content_channel_repos content_channel_repos_pinned_run_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.content_channel_repos
    ADD CONSTRAINT content_channel_repos_pinned_run_id_fkey FOREIGN KEY (pinned_run_id) REFERENCES public.mirror_sync_runs(id) ON DELETE SET NULL;


--
-- Name: content_profile_channels content_profile_channels_channel_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.content_profile_channels
    ADD CONSTRAINT content_profile_channels_channel_id_fkey FOREIGN KEY (channel_id) REFERENCES public.content_channels(id) ON DELETE CASCADE;


--
-- Name: content_profile_channels content_profile_channels_profile_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.content_profile_channels
    ADD CONSTRAINT content_profile_channels_profile_id_fkey FOREIGN KEY (profile_id) REFERENCES public.content_profiles(id) ON DELETE CASCADE;


--
-- Name: file_transfer_audits file_transfer_audits_system_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.file_transfer_audits
    ADD CONSTRAINT file_transfer_audits_system_id_fkey FOREIGN KEY (system_id) REFERENCES public.systems(id) ON DELETE SET NULL;


--
-- Name: file_transfer_audits file_transfer_audits_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.file_transfer_audits
    ADD CONSTRAINT file_transfer_audits_user_id_fkey FOREIGN KEY (user_id) REFERENCES public."user"(id) ON DELETE SET NULL;


--
-- Name: patch_update_plans fk_patch_update_plans_archived_by_user; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_update_plans
    ADD CONSTRAINT fk_patch_update_plans_archived_by_user FOREIGN KEY (archived_by) REFERENCES public."user"(id) ON DELETE SET NULL;


--
-- Name: fleet_operation_results fleet_operation_results_fleet_operation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.fleet_operation_results
    ADD CONSTRAINT fleet_operation_results_fleet_operation_id_fkey FOREIGN KEY (fleet_operation_id) REFERENCES public.fleet_operations(id) ON DELETE CASCADE;


--
-- Name: fleet_operation_results fleet_operation_results_system_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.fleet_operation_results
    ADD CONSTRAINT fleet_operation_results_system_id_fkey FOREIGN KEY (system_id) REFERENCES public.systems(id) ON DELETE SET NULL;


--
-- Name: fleet_operations fleet_operations_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.fleet_operations
    ADD CONSTRAINT fleet_operations_user_id_fkey FOREIGN KEY (user_id) REFERENCES public."user"(id);


--
-- Name: group_content_profile_subscriptions group_content_profile_subscriptions_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.group_content_profile_subscriptions
    ADD CONSTRAINT group_content_profile_subscriptions_group_id_fkey FOREIGN KEY (group_id) REFERENCES public.groups(id) ON DELETE CASCADE;


--
-- Name: group_content_profile_subscriptions group_content_profile_subscriptions_profile_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.group_content_profile_subscriptions
    ADD CONSTRAINT group_content_profile_subscriptions_profile_id_fkey FOREIGN KEY (profile_id) REFERENCES public.content_profiles(id) ON DELETE CASCADE;


--
-- Name: groups groups_parent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.groups
    ADD CONSTRAINT groups_parent_id_fkey FOREIGN KEY (parent_id) REFERENCES public.groups(id) ON DELETE SET NULL;


--
-- Name: host_content_profile_subscriptions host_content_profile_subscriptions_host_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.host_content_profile_subscriptions
    ADD CONSTRAINT host_content_profile_subscriptions_host_id_fkey FOREIGN KEY (host_id) REFERENCES public.systems(id) ON DELETE CASCADE;


--
-- Name: host_content_profile_subscriptions host_content_profile_subscriptions_profile_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.host_content_profile_subscriptions
    ADD CONSTRAINT host_content_profile_subscriptions_profile_id_fkey FOREIGN KEY (profile_id) REFERENCES public.content_profiles(id) ON DELETE CASCADE;


--
-- Name: host_facts host_facts_system_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.host_facts
    ADD CONSTRAINT host_facts_system_id_fkey FOREIGN KEY (system_id) REFERENCES public.systems(id) ON DELETE CASCADE;


--
-- Name: host_mirror_serve_credentials host_mirror_serve_credentials_host_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.host_mirror_serve_credentials
    ADD CONSTRAINT host_mirror_serve_credentials_host_id_fkey FOREIGN KEY (host_id) REFERENCES public.systems(id) ON DELETE CASCADE;


--
-- Name: host_mirror_serve_credentials host_mirror_serve_credentials_mirror_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.host_mirror_serve_credentials
    ADD CONSTRAINT host_mirror_serve_credentials_mirror_id_fkey FOREIGN KEY (mirror_id) REFERENCES public.mirror_repos(id) ON DELETE CASCADE;


--
-- Name: host_mirror_trust host_mirror_trust_host_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.host_mirror_trust
    ADD CONSTRAINT host_mirror_trust_host_id_fkey FOREIGN KEY (host_id) REFERENCES public.systems(id) ON DELETE CASCADE;


--
-- Name: host_mirror_trust host_mirror_trust_mirror_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.host_mirror_trust
    ADD CONSTRAINT host_mirror_trust_mirror_id_fkey FOREIGN KEY (mirror_id) REFERENCES public.mirror_repos(id) ON DELETE CASCADE;


--
-- Name: host_user_states host_user_states_system_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.host_user_states
    ADD CONSTRAINT host_user_states_system_id_fkey FOREIGN KEY (system_id) REFERENCES public.systems(id) ON DELETE CASCADE;


--
-- Name: job_history job_history_job_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.job_history
    ADD CONSTRAINT job_history_job_id_fkey FOREIGN KEY (job_id) REFERENCES public.jobs(id);


--
-- Name: jobs jobs_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.jobs
    ADD CONSTRAINT jobs_created_by_fkey FOREIGN KEY (created_by) REFERENCES public."user"(id);


--
-- Name: jobs jobs_depends_on_job_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.jobs
    ADD CONSTRAINT jobs_depends_on_job_id_fkey FOREIGN KEY (depends_on_job_id) REFERENCES public.jobs(id) ON DELETE SET NULL;


--
-- Name: lifecycle_notification_state lifecycle_notification_state_system_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.lifecycle_notification_state
    ADD CONSTRAINT lifecycle_notification_state_system_id_fkey FOREIGN KEY (system_id) REFERENCES public.systems(id) ON DELETE CASCADE;


--
-- Name: maintenance_windows maintenance_windows_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.maintenance_windows
    ADD CONSTRAINT maintenance_windows_created_by_fkey FOREIGN KEY (created_by) REFERENCES public."user"(id);


--
-- Name: mirror_alert_state mirror_alert_state_mirror_repo_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mirror_alert_state
    ADD CONSTRAINT mirror_alert_state_mirror_repo_id_fkey FOREIGN KEY (mirror_repo_id) REFERENCES public.mirror_repos(id) ON DELETE CASCADE;


--
-- Name: mirror_signing_keys mirror_signing_keys_mirror_repo_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mirror_signing_keys
    ADD CONSTRAINT mirror_signing_keys_mirror_repo_id_fkey FOREIGN KEY (mirror_repo_id) REFERENCES public.mirror_repos(id) ON DELETE CASCADE;


--
-- Name: mirror_sync_run_packages mirror_sync_run_packages_mirror_repo_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mirror_sync_run_packages
    ADD CONSTRAINT mirror_sync_run_packages_mirror_repo_id_fkey FOREIGN KEY (mirror_repo_id) REFERENCES public.mirror_repos(id) ON DELETE CASCADE;


--
-- Name: mirror_sync_run_packages mirror_sync_run_packages_mirror_sync_run_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mirror_sync_run_packages
    ADD CONSTRAINT mirror_sync_run_packages_mirror_sync_run_id_fkey FOREIGN KEY (mirror_sync_run_id) REFERENCES public.mirror_sync_runs(id) ON DELETE CASCADE;


--
-- Name: mirror_sync_runs mirror_sync_runs_mirror_repo_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mirror_sync_runs
    ADD CONSTRAINT mirror_sync_runs_mirror_repo_id_fkey FOREIGN KEY (mirror_repo_id) REFERENCES public.mirror_repos(id) ON DELETE CASCADE;


--
-- Name: mirror_sync_runs mirror_sync_runs_signed_with_key_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mirror_sync_runs
    ADD CONSTRAINT mirror_sync_runs_signed_with_key_id_fkey FOREIGN KEY (signed_with_key_id) REFERENCES public.mirror_signing_keys(id) ON DELETE SET NULL;


--
-- Name: notification_preferences notification_preferences_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.notification_preferences
    ADD CONSTRAINT notification_preferences_user_id_fkey FOREIGN KEY (user_id) REFERENCES public."user"(id);


--
-- Name: notifications notifications_related_job_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.notifications
    ADD CONSTRAINT notifications_related_job_id_fkey FOREIGN KEY (related_job_id) REFERENCES public.jobs(id);


--
-- Name: notifications notifications_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.notifications
    ADD CONSTRAINT notifications_user_id_fkey FOREIGN KEY (user_id) REFERENCES public."user"(id);


--
-- Name: package_history package_history_job_history_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.package_history
    ADD CONSTRAINT package_history_job_history_id_fkey FOREIGN KEY (job_history_id) REFERENCES public.job_history(id);


--
-- Name: package_history package_history_package_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.package_history
    ADD CONSTRAINT package_history_package_id_fkey FOREIGN KEY (package_id) REFERENCES public.packages(id);


--
-- Name: package_history package_history_performed_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.package_history
    ADD CONSTRAINT package_history_performed_by_fkey FOREIGN KEY (performed_by) REFERENCES public."user"(id);


--
-- Name: package_history package_history_system_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.package_history
    ADD CONSTRAINT package_history_system_id_fkey FOREIGN KEY (system_id) REFERENCES public.systems(id);


--
-- Name: package_updates package_updates_package_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.package_updates
    ADD CONSTRAINT package_updates_package_id_fkey FOREIGN KEY (package_id) REFERENCES public.packages(id);


--
-- Name: package_updates package_updates_system_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.package_updates
    ADD CONSTRAINT package_updates_system_id_fkey FOREIGN KEY (system_id) REFERENCES public.systems(id);


--
-- Name: packages packages_system_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.packages
    ADD CONSTRAINT packages_system_id_fkey FOREIGN KEY (system_id) REFERENCES public.systems(id);


--
-- Name: patch_advisory_fixed_packages patch_advisory_fixed_packages_advisory_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_advisory_fixed_packages
    ADD CONSTRAINT patch_advisory_fixed_packages_advisory_id_fkey FOREIGN KEY (advisory_id) REFERENCES public.patch_advisories(id) ON DELETE CASCADE;


--
-- Name: patch_advisory_host_applicability patch_advisory_host_applicability_advisory_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_advisory_host_applicability
    ADD CONSTRAINT patch_advisory_host_applicability_advisory_id_fkey FOREIGN KEY (advisory_id) REFERENCES public.patch_advisories(id) ON DELETE CASCADE;


--
-- Name: patch_advisory_host_applicability patch_advisory_host_applicability_fixed_package_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_advisory_host_applicability
    ADD CONSTRAINT patch_advisory_host_applicability_fixed_package_id_fkey FOREIGN KEY (fixed_package_id) REFERENCES public.patch_advisory_fixed_packages(id) ON DELETE SET NULL;


--
-- Name: patch_advisory_host_applicability patch_advisory_host_applicability_system_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_advisory_host_applicability
    ADD CONSTRAINT patch_advisory_host_applicability_system_id_fkey FOREIGN KEY (system_id) REFERENCES public.systems(id) ON DELETE CASCADE;


--
-- Name: patch_advisory_imports patch_advisory_imports_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_advisory_imports
    ADD CONSTRAINT patch_advisory_imports_created_by_fkey FOREIGN KEY (created_by) REFERENCES public."user"(id);


--
-- Name: patch_approval_votes patch_approval_votes_approval_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_approval_votes
    ADD CONSTRAINT patch_approval_votes_approval_id_fkey FOREIGN KEY (approval_id) REFERENCES public.patch_approvals(id) ON DELETE CASCADE;


--
-- Name: patch_approval_votes patch_approval_votes_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_approval_votes
    ADD CONSTRAINT patch_approval_votes_user_id_fkey FOREIGN KEY (user_id) REFERENCES public."user"(id);


--
-- Name: patch_approvals patch_approvals_decided_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_approvals
    ADD CONSTRAINT patch_approvals_decided_by_fkey FOREIGN KEY (decided_by) REFERENCES public."user"(id);


--
-- Name: patch_approvals patch_approvals_requested_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_approvals
    ADD CONSTRAINT patch_approvals_requested_by_fkey FOREIGN KEY (requested_by) REFERENCES public."user"(id);


--
-- Name: patch_policies patch_policies_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_policies
    ADD CONSTRAINT patch_policies_created_by_fkey FOREIGN KEY (created_by) REFERENCES public."user"(id);


--
-- Name: patch_policies patch_policies_maintenance_window_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_policies
    ADD CONSTRAINT patch_policies_maintenance_window_id_fkey FOREIGN KEY (maintenance_window_id) REFERENCES public.maintenance_windows(id) ON DELETE SET NULL;


--
-- Name: patch_policies patch_policies_reboot_window_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_policies
    ADD CONSTRAINT patch_policies_reboot_window_id_fkey FOREIGN KEY (reboot_window_id) REFERENCES public.maintenance_windows(id) ON DELETE SET NULL;


--
-- Name: patch_policy_group_bindings patch_policy_group_bindings_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_policy_group_bindings
    ADD CONSTRAINT patch_policy_group_bindings_created_by_fkey FOREIGN KEY (created_by) REFERENCES public."user"(id);


--
-- Name: patch_policy_group_bindings patch_policy_group_bindings_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_policy_group_bindings
    ADD CONSTRAINT patch_policy_group_bindings_group_id_fkey FOREIGN KEY (group_id) REFERENCES public.groups(id) ON DELETE CASCADE;


--
-- Name: patch_policy_group_bindings patch_policy_group_bindings_policy_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_policy_group_bindings
    ADD CONSTRAINT patch_policy_group_bindings_policy_id_fkey FOREIGN KEY (policy_id) REFERENCES public.patch_policies(id) ON DELETE CASCADE;


--
-- Name: patch_policy_host_bindings patch_policy_host_bindings_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_policy_host_bindings
    ADD CONSTRAINT patch_policy_host_bindings_created_by_fkey FOREIGN KEY (created_by) REFERENCES public."user"(id);


--
-- Name: patch_policy_host_bindings patch_policy_host_bindings_policy_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_policy_host_bindings
    ADD CONSTRAINT patch_policy_host_bindings_policy_id_fkey FOREIGN KEY (policy_id) REFERENCES public.patch_policies(id) ON DELETE CASCADE;


--
-- Name: patch_policy_host_bindings patch_policy_host_bindings_system_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_policy_host_bindings
    ADD CONSTRAINT patch_policy_host_bindings_system_id_fkey FOREIGN KEY (system_id) REFERENCES public.systems(id) ON DELETE CASCADE;


--
-- Name: patch_policy_ring_bindings patch_policy_ring_bindings_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_policy_ring_bindings
    ADD CONSTRAINT patch_policy_ring_bindings_created_by_fkey FOREIGN KEY (created_by) REFERENCES public."user"(id);


--
-- Name: patch_policy_ring_bindings patch_policy_ring_bindings_policy_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_policy_ring_bindings
    ADD CONSTRAINT patch_policy_ring_bindings_policy_id_fkey FOREIGN KEY (policy_id) REFERENCES public.patch_policies(id) ON DELETE CASCADE;


--
-- Name: patch_policy_ring_bindings patch_policy_ring_bindings_ring_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_policy_ring_bindings
    ADD CONSTRAINT patch_policy_ring_bindings_ring_id_fkey FOREIGN KEY (ring_id) REFERENCES public.patch_rings(id) ON DELETE CASCADE;


--
-- Name: patch_policy_smart_group_bindings patch_policy_smart_group_bindings_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_policy_smart_group_bindings
    ADD CONSTRAINT patch_policy_smart_group_bindings_created_by_fkey FOREIGN KEY (created_by) REFERENCES public."user"(id);


--
-- Name: patch_policy_smart_group_bindings patch_policy_smart_group_bindings_policy_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_policy_smart_group_bindings
    ADD CONSTRAINT patch_policy_smart_group_bindings_policy_id_fkey FOREIGN KEY (policy_id) REFERENCES public.patch_policies(id) ON DELETE CASCADE;


--
-- Name: patch_policy_smart_group_bindings patch_policy_smart_group_bindings_smart_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_policy_smart_group_bindings
    ADD CONSTRAINT patch_policy_smart_group_bindings_smart_group_id_fkey FOREIGN KEY (smart_group_id) REFERENCES public.smart_groups(id) ON DELETE CASCADE;


--
-- Name: patch_ring_gate_definitions patch_ring_gate_definitions_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_ring_gate_definitions
    ADD CONSTRAINT patch_ring_gate_definitions_created_by_fkey FOREIGN KEY (created_by) REFERENCES public."user"(id);


--
-- Name: patch_ring_gate_definitions patch_ring_gate_definitions_ring_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_ring_gate_definitions
    ADD CONSTRAINT patch_ring_gate_definitions_ring_id_fkey FOREIGN KEY (ring_id) REFERENCES public.patch_rings(id) ON DELETE CASCADE;


--
-- Name: patch_ring_gate_signals patch_ring_gate_signals_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_ring_gate_signals
    ADD CONSTRAINT patch_ring_gate_signals_created_by_fkey FOREIGN KEY (created_by) REFERENCES public."user"(id);


--
-- Name: patch_ring_gate_signals patch_ring_gate_signals_gate_definition_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_ring_gate_signals
    ADD CONSTRAINT patch_ring_gate_signals_gate_definition_id_fkey FOREIGN KEY (gate_definition_id) REFERENCES public.patch_ring_gate_definitions(id) ON DELETE SET NULL;


--
-- Name: patch_ring_gate_signals patch_ring_gate_signals_ring_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_ring_gate_signals
    ADD CONSTRAINT patch_ring_gate_signals_ring_id_fkey FOREIGN KEY (ring_id) REFERENCES public.patch_rings(id) ON DELETE CASCADE;


--
-- Name: patch_ring_group_bindings patch_ring_group_bindings_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_ring_group_bindings
    ADD CONSTRAINT patch_ring_group_bindings_created_by_fkey FOREIGN KEY (created_by) REFERENCES public."user"(id);


--
-- Name: patch_ring_group_bindings patch_ring_group_bindings_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_ring_group_bindings
    ADD CONSTRAINT patch_ring_group_bindings_group_id_fkey FOREIGN KEY (group_id) REFERENCES public.groups(id) ON DELETE CASCADE;


--
-- Name: patch_ring_group_bindings patch_ring_group_bindings_ring_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_ring_group_bindings
    ADD CONSTRAINT patch_ring_group_bindings_ring_id_fkey FOREIGN KEY (ring_id) REFERENCES public.patch_rings(id) ON DELETE CASCADE;


--
-- Name: patch_ring_host_bindings patch_ring_host_bindings_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_ring_host_bindings
    ADD CONSTRAINT patch_ring_host_bindings_created_by_fkey FOREIGN KEY (created_by) REFERENCES public."user"(id);


--
-- Name: patch_ring_host_bindings patch_ring_host_bindings_ring_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_ring_host_bindings
    ADD CONSTRAINT patch_ring_host_bindings_ring_id_fkey FOREIGN KEY (ring_id) REFERENCES public.patch_rings(id) ON DELETE CASCADE;


--
-- Name: patch_ring_host_bindings patch_ring_host_bindings_system_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_ring_host_bindings
    ADD CONSTRAINT patch_ring_host_bindings_system_id_fkey FOREIGN KEY (system_id) REFERENCES public.systems(id) ON DELETE CASCADE;


--
-- Name: patch_ring_smart_group_bindings patch_ring_smart_group_bindings_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_ring_smart_group_bindings
    ADD CONSTRAINT patch_ring_smart_group_bindings_created_by_fkey FOREIGN KEY (created_by) REFERENCES public."user"(id);


--
-- Name: patch_ring_smart_group_bindings patch_ring_smart_group_bindings_ring_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_ring_smart_group_bindings
    ADD CONSTRAINT patch_ring_smart_group_bindings_ring_id_fkey FOREIGN KEY (ring_id) REFERENCES public.patch_rings(id) ON DELETE CASCADE;


--
-- Name: patch_ring_smart_group_bindings patch_ring_smart_group_bindings_smart_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_ring_smart_group_bindings
    ADD CONSTRAINT patch_ring_smart_group_bindings_smart_group_id_fkey FOREIGN KEY (smart_group_id) REFERENCES public.smart_groups(id) ON DELETE CASCADE;


--
-- Name: patch_rings patch_rings_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_rings
    ADD CONSTRAINT patch_rings_created_by_fkey FOREIGN KEY (created_by) REFERENCES public."user"(id);


--
-- Name: patch_rollback_dispatch_host_packages patch_rollback_dispatch_host_pac_rollback_dispatch_host_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_rollback_dispatch_host_packages
    ADD CONSTRAINT patch_rollback_dispatch_host_pac_rollback_dispatch_host_id_fkey FOREIGN KEY (rollback_dispatch_host_id) REFERENCES public.patch_rollback_dispatch_hosts(id) ON DELETE CASCADE;


--
-- Name: patch_rollback_dispatch_host_packages patch_rollback_dispatch_host_packages_rollback_package_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_rollback_dispatch_host_packages
    ADD CONSTRAINT patch_rollback_dispatch_host_packages_rollback_package_id_fkey FOREIGN KEY (rollback_package_id) REFERENCES public.patch_update_execution_rollback_packages(id) ON DELETE SET NULL;


--
-- Name: patch_rollback_dispatch_hosts patch_rollback_dispatch_hosts_rollback_dispatch_run_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_rollback_dispatch_hosts
    ADD CONSTRAINT patch_rollback_dispatch_hosts_rollback_dispatch_run_id_fkey FOREIGN KEY (rollback_dispatch_run_id) REFERENCES public.patch_rollback_dispatch_runs(id) ON DELETE CASCADE;


--
-- Name: patch_rollback_dispatch_hosts patch_rollback_dispatch_hosts_rollback_host_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_rollback_dispatch_hosts
    ADD CONSTRAINT patch_rollback_dispatch_hosts_rollback_host_id_fkey FOREIGN KEY (rollback_host_id) REFERENCES public.patch_update_execution_rollback_hosts(id) ON DELETE CASCADE;


--
-- Name: patch_rollback_dispatch_runs patch_rollback_dispatch_runs_rollback_approval_link_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_rollback_dispatch_runs
    ADD CONSTRAINT patch_rollback_dispatch_runs_rollback_approval_link_id_fkey FOREIGN KEY (rollback_approval_link_id) REFERENCES public.patch_update_execution_rollback_approvals(id) ON DELETE RESTRICT;


--
-- Name: patch_rollback_dispatch_runs patch_rollback_dispatch_runs_rollback_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_rollback_dispatch_runs
    ADD CONSTRAINT patch_rollback_dispatch_runs_rollback_id_fkey FOREIGN KEY (rollback_id) REFERENCES public.patch_update_execution_rollbacks(id) ON DELETE CASCADE;


--
-- Name: patch_rollback_dispatch_runs patch_rollback_dispatch_runs_started_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_rollback_dispatch_runs
    ADD CONSTRAINT patch_rollback_dispatch_runs_started_by_fkey FOREIGN KEY (started_by) REFERENCES public."user"(id);


--
-- Name: patch_update_execution_host_packages patch_update_execution_host_packages_execution_host_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_update_execution_host_packages
    ADD CONSTRAINT patch_update_execution_host_packages_execution_host_id_fkey FOREIGN KEY (execution_host_id) REFERENCES public.patch_update_execution_hosts(id) ON DELETE CASCADE;


--
-- Name: patch_update_execution_hosts patch_update_execution_hosts_execution_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_update_execution_hosts
    ADD CONSTRAINT patch_update_execution_hosts_execution_id_fkey FOREIGN KEY (execution_id) REFERENCES public.patch_update_executions(id) ON DELETE CASCADE;


--
-- Name: patch_update_execution_hosts patch_update_execution_hosts_plan_host_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_update_execution_hosts
    ADD CONSTRAINT patch_update_execution_hosts_plan_host_id_fkey FOREIGN KEY (plan_host_id) REFERENCES public.patch_update_plan_hosts(id) ON DELETE RESTRICT;


--
-- Name: patch_update_execution_reboots patch_update_execution_reboots_execution_host_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_update_execution_reboots
    ADD CONSTRAINT patch_update_execution_reboots_execution_host_id_fkey FOREIGN KEY (execution_host_id) REFERENCES public.patch_update_execution_hosts(id) ON DELETE CASCADE;


--
-- Name: patch_update_execution_reboots patch_update_execution_reboots_execution_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_update_execution_reboots
    ADD CONSTRAINT patch_update_execution_reboots_execution_id_fkey FOREIGN KEY (execution_id) REFERENCES public.patch_update_executions(id) ON DELETE CASCADE;


--
-- Name: patch_update_execution_rollback_packages patch_update_execution_rollback__execution_host_package_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_update_execution_rollback_packages
    ADD CONSTRAINT patch_update_execution_rollback__execution_host_package_id_fkey FOREIGN KEY (execution_host_package_id) REFERENCES public.patch_update_execution_host_packages(id) ON DELETE SET NULL;


--
-- Name: patch_update_execution_rollback_approvals patch_update_execution_rollback_approvals_approval_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_update_execution_rollback_approvals
    ADD CONSTRAINT patch_update_execution_rollback_approvals_approval_id_fkey FOREIGN KEY (approval_id) REFERENCES public.patch_approvals(id) ON DELETE RESTRICT;


--
-- Name: patch_update_execution_rollback_approvals patch_update_execution_rollback_approvals_requested_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_update_execution_rollback_approvals
    ADD CONSTRAINT patch_update_execution_rollback_approvals_requested_by_fkey FOREIGN KEY (requested_by) REFERENCES public."user"(id);


--
-- Name: patch_update_execution_rollback_approvals patch_update_execution_rollback_approvals_rollback_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_update_execution_rollback_approvals
    ADD CONSTRAINT patch_update_execution_rollback_approvals_rollback_id_fkey FOREIGN KEY (rollback_id) REFERENCES public.patch_update_execution_rollbacks(id) ON DELETE CASCADE;


--
-- Name: patch_update_execution_rollback_hosts patch_update_execution_rollback_hosts_execution_host_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_update_execution_rollback_hosts
    ADD CONSTRAINT patch_update_execution_rollback_hosts_execution_host_id_fkey FOREIGN KEY (execution_host_id) REFERENCES public.patch_update_execution_hosts(id) ON DELETE CASCADE;


--
-- Name: patch_update_execution_rollback_hosts patch_update_execution_rollback_hosts_rollback_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_update_execution_rollback_hosts
    ADD CONSTRAINT patch_update_execution_rollback_hosts_rollback_id_fkey FOREIGN KEY (rollback_id) REFERENCES public.patch_update_execution_rollbacks(id) ON DELETE CASCADE;


--
-- Name: patch_update_execution_rollback_packages patch_update_execution_rollback_packages_rollback_host_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_update_execution_rollback_packages
    ADD CONSTRAINT patch_update_execution_rollback_packages_rollback_host_id_fkey FOREIGN KEY (rollback_host_id) REFERENCES public.patch_update_execution_rollback_hosts(id) ON DELETE CASCADE;


--
-- Name: patch_update_execution_rollbacks patch_update_execution_rollbacks_execution_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_update_execution_rollbacks
    ADD CONSTRAINT patch_update_execution_rollbacks_execution_id_fkey FOREIGN KEY (execution_id) REFERENCES public.patch_update_executions(id) ON DELETE CASCADE;


--
-- Name: patch_update_executions patch_update_executions_plan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_update_executions
    ADD CONSTRAINT patch_update_executions_plan_id_fkey FOREIGN KEY (plan_id) REFERENCES public.patch_update_plans(id) ON DELETE RESTRICT;


--
-- Name: patch_update_executions patch_update_executions_started_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_update_executions
    ADD CONSTRAINT patch_update_executions_started_by_fkey FOREIGN KEY (started_by) REFERENCES public."user"(id);


--
-- Name: patch_update_plan_approvals patch_update_plan_approvals_approval_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_update_plan_approvals
    ADD CONSTRAINT patch_update_plan_approvals_approval_id_fkey FOREIGN KEY (approval_id) REFERENCES public.patch_approvals(id) ON DELETE RESTRICT;


--
-- Name: patch_update_plan_approvals patch_update_plan_approvals_plan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_update_plan_approvals
    ADD CONSTRAINT patch_update_plan_approvals_plan_id_fkey FOREIGN KEY (plan_id) REFERENCES public.patch_update_plans(id) ON DELETE CASCADE;


--
-- Name: patch_update_plan_approvals patch_update_plan_approvals_requested_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_update_plan_approvals
    ADD CONSTRAINT patch_update_plan_approvals_requested_by_fkey FOREIGN KEY (requested_by) REFERENCES public."user"(id);


--
-- Name: patch_update_plan_hosts patch_update_plan_hosts_plan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_update_plan_hosts
    ADD CONSTRAINT patch_update_plan_hosts_plan_id_fkey FOREIGN KEY (plan_id) REFERENCES public.patch_update_plans(id) ON DELETE CASCADE;


--
-- Name: patch_update_plan_hosts patch_update_plan_hosts_system_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_update_plan_hosts
    ADD CONSTRAINT patch_update_plan_hosts_system_id_fkey FOREIGN KEY (system_id) REFERENCES public.systems(id) ON DELETE SET NULL;


--
-- Name: patch_update_plan_preflight_snapshots patch_update_plan_preflight_snapshots_plan_host_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_update_plan_preflight_snapshots
    ADD CONSTRAINT patch_update_plan_preflight_snapshots_plan_host_id_fkey FOREIGN KEY (plan_host_id) REFERENCES public.patch_update_plan_hosts(id) ON DELETE CASCADE;


--
-- Name: patch_update_plan_selected_packages patch_update_plan_selected_packages_advisory_id_snapshot_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_update_plan_selected_packages
    ADD CONSTRAINT patch_update_plan_selected_packages_advisory_id_snapshot_fkey FOREIGN KEY (advisory_id_snapshot) REFERENCES public.patch_advisories(id) ON DELETE SET NULL;


--
-- Name: patch_update_plan_selected_packages patch_update_plan_selected_packages_plan_host_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_update_plan_selected_packages
    ADD CONSTRAINT patch_update_plan_selected_packages_plan_host_id_fkey FOREIGN KEY (plan_host_id) REFERENCES public.patch_update_plan_hosts(id) ON DELETE CASCADE;


--
-- Name: patch_update_plans patch_update_plans_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_update_plans
    ADD CONSTRAINT patch_update_plans_created_by_fkey FOREIGN KEY (created_by) REFERENCES public."user"(id);


--
-- Name: patch_update_plans patch_update_plans_maintenance_window_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_update_plans
    ADD CONSTRAINT patch_update_plans_maintenance_window_id_fkey FOREIGN KEY (maintenance_window_id) REFERENCES public.maintenance_windows(id) ON DELETE SET NULL;


--
-- Name: patch_update_plans patch_update_plans_policy_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_update_plans
    ADD CONSTRAINT patch_update_plans_policy_id_fkey FOREIGN KEY (policy_id) REFERENCES public.patch_policies(id) ON DELETE RESTRICT;


--
-- Name: patch_update_plans patch_update_plans_reboot_window_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.patch_update_plans
    ADD CONSTRAINT patch_update_plans_reboot_window_id_fkey FOREIGN KEY (reboot_window_id) REFERENCES public.maintenance_windows(id) ON DELETE SET NULL;


--
-- Name: recordings recordings_session_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.recordings
    ADD CONSTRAINT recordings_session_id_fkey FOREIGN KEY (session_id) REFERENCES public.sessions(id) ON DELETE CASCADE;


--
-- Name: recordings recordings_system_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.recordings
    ADD CONSTRAINT recordings_system_id_fkey FOREIGN KEY (system_id) REFERENCES public.systems(id) ON DELETE SET NULL;


--
-- Name: recordings recordings_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.recordings
    ADD CONSTRAINT recordings_user_id_fkey FOREIGN KEY (user_id) REFERENCES public."user"(id) ON DELETE SET NULL;


--
-- Name: refresh_tokens refresh_tokens_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.refresh_tokens
    ADD CONSTRAINT refresh_tokens_user_id_fkey FOREIGN KEY (user_id) REFERENCES public."user"(id);


--
-- Name: repo_sources repo_sources_system_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.repo_sources
    ADD CONSTRAINT repo_sources_system_id_fkey FOREIGN KEY (system_id) REFERENCES public.systems(id);


--
-- Name: report_runs report_runs_triggered_by_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.report_runs
    ADD CONSTRAINT report_runs_triggered_by_user_id_fkey FOREIGN KEY (triggered_by_user_id) REFERENCES public."user"(id) ON DELETE SET NULL;


--
-- Name: report_schedules report_schedules_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.report_schedules
    ADD CONSTRAINT report_schedules_created_by_fkey FOREIGN KEY (created_by) REFERENCES public."user"(id) ON DELETE SET NULL;


--
-- Name: revocation_work revocation_work_system_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.revocation_work
    ADD CONSTRAINT revocation_work_system_id_fkey FOREIGN KEY (system_id) REFERENCES public.systems(id) ON DELETE CASCADE;


--
-- Name: revocation_work revocation_work_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.revocation_work
    ADD CONSTRAINT revocation_work_user_id_fkey FOREIGN KEY (user_id) REFERENCES public."user"(id) ON DELETE SET NULL;


--
-- Name: saved_views saved_views_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.saved_views
    ADD CONSTRAINT saved_views_user_id_fkey FOREIGN KEY (user_id) REFERENCES public."user"(id);


--
-- Name: session_approvals session_approvals_approver_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.session_approvals
    ADD CONSTRAINT session_approvals_approver_id_fkey FOREIGN KEY (approver_id) REFERENCES public."user"(id) ON DELETE SET NULL;


--
-- Name: session_approvals session_approvals_fleet_role_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.session_approvals
    ADD CONSTRAINT session_approvals_fleet_role_id_fkey FOREIGN KEY (fleet_role_id) REFERENCES public.fleet_roles(id) ON DELETE CASCADE;


--
-- Name: session_approvals session_approvals_requester_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.session_approvals
    ADD CONSTRAINT session_approvals_requester_id_fkey FOREIGN KEY (requester_id) REFERENCES public."user"(id) ON DELETE CASCADE;


--
-- Name: session_approvals session_approvals_system_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.session_approvals
    ADD CONSTRAINT session_approvals_system_id_fkey FOREIGN KEY (system_id) REFERENCES public.systems(id) ON DELETE CASCADE;


--
-- Name: session_locks session_locks_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.session_locks
    ADD CONSTRAINT session_locks_created_by_fkey FOREIGN KEY (created_by) REFERENCES public."user"(id) ON DELETE SET NULL;


--
-- Name: session_locks session_locks_released_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.session_locks
    ADD CONSTRAINT session_locks_released_by_fkey FOREIGN KEY (released_by) REFERENCES public."user"(id) ON DELETE SET NULL;


--
-- Name: session_locks session_locks_subject_app_role_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.session_locks
    ADD CONSTRAINT session_locks_subject_app_role_id_fkey FOREIGN KEY (subject_app_role_id) REFERENCES public.role(id) ON DELETE CASCADE;


--
-- Name: session_locks session_locks_subject_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.session_locks
    ADD CONSTRAINT session_locks_subject_user_id_fkey FOREIGN KEY (subject_user_id) REFERENCES public."user"(id) ON DELETE CASCADE;


--
-- Name: sessions sessions_fleet_role_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sessions
    ADD CONSTRAINT sessions_fleet_role_id_fkey FOREIGN KEY (fleet_role_id) REFERENCES public.fleet_roles(id) ON DELETE SET NULL;


--
-- Name: sessions sessions_system_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sessions
    ADD CONSTRAINT sessions_system_id_fkey FOREIGN KEY (system_id) REFERENCES public.systems(id) ON DELETE CASCADE;


--
-- Name: sessions sessions_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sessions
    ADD CONSTRAINT sessions_user_id_fkey FOREIGN KEY (user_id) REFERENCES public."user"(id) ON DELETE CASCADE;


--
-- Name: smart_group_content_profile_subscriptions smart_group_content_profile_subscriptions_profile_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.smart_group_content_profile_subscriptions
    ADD CONSTRAINT smart_group_content_profile_subscriptions_profile_id_fkey FOREIGN KEY (profile_id) REFERENCES public.content_profiles(id) ON DELETE CASCADE;


--
-- Name: smart_group_content_profile_subscriptions smart_group_content_profile_subscriptions_smart_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.smart_group_content_profile_subscriptions
    ADD CONSTRAINT smart_group_content_profile_subscriptions_smart_group_id_fkey FOREIGN KEY (smart_group_id) REFERENCES public.smart_groups(id) ON DELETE CASCADE;


--
-- Name: smart_group_memberships smart_group_memberships_smart_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.smart_group_memberships
    ADD CONSTRAINT smart_group_memberships_smart_group_id_fkey FOREIGN KEY (smart_group_id) REFERENCES public.smart_groups(id) ON DELETE CASCADE;


--
-- Name: smart_group_memberships smart_group_memberships_system_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.smart_group_memberships
    ADD CONSTRAINT smart_group_memberships_system_id_fkey FOREIGN KEY (system_id) REFERENCES public.systems(id) ON DELETE CASCADE;


--
-- Name: smart_groups smart_groups_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.smart_groups
    ADD CONSTRAINT smart_groups_created_by_fkey FOREIGN KEY (created_by) REFERENCES public."user"(id);


--
-- Name: ssh_host_keys ssh_host_keys_system_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ssh_host_keys
    ADD CONSTRAINT ssh_host_keys_system_id_fkey FOREIGN KEY (system_id) REFERENCES public.systems(id);


--
-- Name: ssh_security_logs ssh_security_logs_system_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ssh_security_logs
    ADD CONSTRAINT ssh_security_logs_system_id_fkey FOREIGN KEY (system_id) REFERENCES public.systems(id);


--
-- Name: ssh_security_policies ssh_security_policies_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ssh_security_policies
    ADD CONSTRAINT ssh_security_policies_created_by_fkey FOREIGN KEY (created_by) REFERENCES public."user"(id);


--
-- Name: system_audits system_audits_changed_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.system_audits
    ADD CONSTRAINT system_audits_changed_by_fkey FOREIGN KEY (changed_by) REFERENCES public."user"(id);


--
-- Name: system_audits system_audits_system_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.system_audits
    ADD CONSTRAINT system_audits_system_id_fkey FOREIGN KEY (system_id) REFERENCES public.systems(id) ON DELETE SET NULL;


--
-- Name: system_metadata system_metadata_system_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.system_metadata
    ADD CONSTRAINT system_metadata_system_id_fkey FOREIGN KEY (system_id) REFERENCES public.systems(id);


--
-- Name: system_tag system_tag_system_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.system_tag
    ADD CONSTRAINT system_tag_system_id_fkey FOREIGN KEY (system_id) REFERENCES public.systems(id) ON DELETE CASCADE;


--
-- Name: system_tag system_tag_tag_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.system_tag
    ADD CONSTRAINT system_tag_tag_id_fkey FOREIGN KEY (tag_id) REFERENCES public.tags(id) ON DELETE CASCADE;


--
-- Name: systems systems_credentials_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.systems
    ADD CONSTRAINT systems_credentials_id_fkey FOREIGN KEY (credentials_id) REFERENCES public.credentials(id);


--
-- Name: systems systems_distro_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.systems
    ADD CONSTRAINT systems_distro_id_fkey FOREIGN KEY (distro_id) REFERENCES public.distros(id);


--
-- Name: systems systems_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.systems
    ADD CONSTRAINT systems_group_id_fkey FOREIGN KEY (group_id) REFERENCES public.groups(id);


--
-- Name: systems systems_registered_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.systems
    ADD CONSTRAINT systems_registered_by_fkey FOREIGN KEY (registered_by) REFERENCES public."user"(id);


--
-- Name: systems systems_ssh_security_policy_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.systems
    ADD CONSTRAINT systems_ssh_security_policy_id_fkey FOREIGN KEY (ssh_security_policy_id) REFERENCES public.ssh_security_policies(id);


--
-- Name: tags tags_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tags
    ADD CONSTRAINT tags_created_by_fkey FOREIGN KEY (created_by) REFERENCES public."user"(id);


--
-- Name: totp_challenges totp_challenges_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.totp_challenges
    ADD CONSTRAINT totp_challenges_user_id_fkey FOREIGN KEY (user_id) REFERENCES public."user"(id) ON DELETE CASCADE;


--
-- Name: user_role user_role_role_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_role
    ADD CONSTRAINT user_role_role_id_fkey FOREIGN KEY (role_id) REFERENCES public.role(id);


--
-- Name: user_role user_role_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_role
    ADD CONSTRAINT user_role_user_id_fkey FOREIGN KEY (user_id) REFERENCES public."user"(id);


--
-- Name: vault_config vault_config_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.vault_config
    ADD CONSTRAINT vault_config_created_by_fkey FOREIGN KEY (created_by) REFERENCES public."user"(id);


--
-- PostgreSQL database dump complete
--

\unrestrict QfLSYGj80L3yDSWT7gXEl1LXAgQaQFD8tfGVTgMHFhxvkQ919OtU1Iuo0FwltQr


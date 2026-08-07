--
-- PostgreSQL database dump
--

\restrict smdc9JJbYQ1coeqGtM2pUyJcoiiSPMJpzpOEzds1wNcoXC6oyiyo3ck42mKRI07

-- Dumped from database version 15.17
-- Dumped by pg_dump version 15.17

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
    updated_at timestamp without time zone DEFAULT now() NOT NULL
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
    updated_at timestamp without time zone DEFAULT now() NOT NULL
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
    updated_at timestamp without time zone DEFAULT now() NOT NULL
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
    transport character varying(8)
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
    consecutive_failures integer DEFAULT 0 NOT NULL
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
-- Name: groups id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.groups ALTER COLUMN id SET DEFAULT nextval('public.groups_id_seq'::regclass);


--
-- Name: host_facts id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.host_facts ALTER COLUMN id SET DEFAULT nextval('public.host_facts_id_seq'::regclass);


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
-- Name: notification_preferences id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.notification_preferences ALTER COLUMN id SET DEFAULT nextval('public.notification_preferences_id_seq'::regclass);


--
-- Name: notifications id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.notifications ALTER COLUMN id SET DEFAULT nextval('public.notifications_id_seq'::regclass);


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
-- Name: role id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role ALTER COLUMN id SET DEFAULT nextval('public.role_id_seq'::regclass);


--
-- Name: saved_views id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.saved_views ALTER COLUMN id SET DEFAULT nextval('public.saved_views_id_seq'::regclass);


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

COPY public.access_grants (id, user_id, system_id, fleet_role_id, login, via_binding_id, is_implicit_admin, created_at, updated_at) FROM stdin;
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
-- Data for Name: alembic_version; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.alembic_version (version_num) FROM stdin;
pra156_lifecycle_notif_state
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
1	app_name	Praxis	2026-05-21 23:35:01.495899	2026-05-21 23:35:01.495899
2	timezone	UTC	2026-05-21 23:35:01.495899	2026-05-21 23:35:01.495899
3	date_format	YYYY-MM-DD	2026-05-21 23:35:01.495899	2026-05-21 23:35:01.495899
4	time_format	24h	2026-05-21 23:35:01.495899	2026-05-21 23:35:01.495899
\.


--
-- Data for Name: audit_events; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.audit_events (id, schema_version, event_uuid, "timestamp", action, outcome, actor_user_id, actor_username, actor_ip, target_system_id, target_kind, target_id, context_json, created_at, updated_at) FROM stdin;
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
\.


--
-- Data for Name: command_whitelist; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.command_whitelist (id, name, description, command_pattern, is_regex, is_active, risk_level, category, requires_sudo, timeout_seconds, created_at, updated_at, created_by, requires_approval, required_approvals) FROM stdin;
\.


--
-- Data for Name: credentials; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.credentials (id, name, auth_method, username, created_at, updated_at, sudo_method, vault_path) FROM stdin;
\.


--
-- Data for Name: distro_lifecycle; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.distro_lifecycle (id, distro_id, release, eol_date, support_kind, source, as_of, created_at, updated_at) FROM stdin;
1	ubuntu	14.04	2019-04-25	standard	endoflife.date	2026-05-02	2026-05-21 23:35:01.495899	2026-05-21 23:35:01.495899
2	ubuntu	14.04	2024-04-30	esm	endoflife.date	2026-05-02	2026-05-21 23:35:01.495899	2026-05-21 23:35:01.495899
3	ubuntu	16.04	2021-04-30	standard	endoflife.date	2026-05-02	2026-05-21 23:35:01.495899	2026-05-21 23:35:01.495899
4	ubuntu	16.04	2026-04-30	esm	endoflife.date	2026-05-02	2026-05-21 23:35:01.495899	2026-05-21 23:35:01.495899
5	ubuntu	18.04	2023-05-31	standard	endoflife.date	2026-05-02	2026-05-21 23:35:01.495899	2026-05-21 23:35:01.495899
6	ubuntu	18.04	2028-05-31	esm	endoflife.date	2026-05-02	2026-05-21 23:35:01.495899	2026-05-21 23:35:01.495899
7	ubuntu	20.04	2025-04-29	standard	endoflife.date	2026-05-02	2026-05-21 23:35:01.495899	2026-05-21 23:35:01.495899
8	ubuntu	20.04	2030-04-29	esm	endoflife.date	2026-05-02	2026-05-21 23:35:01.495899	2026-05-21 23:35:01.495899
9	ubuntu	22.04	2027-06-01	standard	endoflife.date	2026-05-02	2026-05-21 23:35:01.495899	2026-05-21 23:35:01.495899
10	ubuntu	22.04	2032-06-01	esm	endoflife.date	2026-05-02	2026-05-21 23:35:01.495899	2026-05-21 23:35:01.495899
11	ubuntu	24.04	2029-06-01	standard	endoflife.date	2026-05-02	2026-05-21 23:35:01.495899	2026-05-21 23:35:01.495899
12	ubuntu	24.04	2034-06-01	esm	endoflife.date	2026-05-02	2026-05-21 23:35:01.495899	2026-05-21 23:35:01.495899
13	rhel	7	2024-06-30	standard	endoflife.date	2026-05-02	2026-05-21 23:35:01.495899	2026-05-21 23:35:01.495899
14	rhel	7	2028-06-30	extended	endoflife.date	2026-05-02	2026-05-21 23:35:01.495899	2026-05-21 23:35:01.495899
15	rhel	8	2029-05-31	standard	endoflife.date	2026-05-02	2026-05-21 23:35:01.495899	2026-05-21 23:35:01.495899
16	rhel	9	2032-05-31	standard	endoflife.date	2026-05-02	2026-05-21 23:35:01.495899	2026-05-21 23:35:01.495899
17	rocky	8	2029-05-31	standard	endoflife.date	2026-05-02	2026-05-21 23:35:01.495899	2026-05-21 23:35:01.495899
18	rocky	9	2032-05-31	standard	endoflife.date	2026-05-02	2026-05-21 23:35:01.495899	2026-05-21 23:35:01.495899
19	almalinux	8	2029-03-01	standard	endoflife.date	2026-05-02	2026-05-21 23:35:01.495899	2026-05-21 23:35:01.495899
20	almalinux	9	2032-05-31	standard	endoflife.date	2026-05-02	2026-05-21 23:35:01.495899	2026-05-21 23:35:01.495899
21	debian	10	2022-09-10	standard	endoflife.date	2026-05-02	2026-05-21 23:35:01.495899	2026-05-21 23:35:01.495899
22	debian	10	2024-06-30	extended	endoflife.date	2026-05-02	2026-05-21 23:35:01.495899	2026-05-21 23:35:01.495899
23	debian	11	2024-08-14	standard	endoflife.date	2026-05-02	2026-05-21 23:35:01.495899	2026-05-21 23:35:01.495899
24	debian	11	2026-08-31	extended	endoflife.date	2026-05-02	2026-05-21 23:35:01.495899	2026-05-21 23:35:01.495899
25	debian	12	2026-06-10	standard	endoflife.date	2026-05-02	2026-05-21 23:35:01.495899	2026-05-21 23:35:01.495899
26	debian	12	2028-06-30	extended	endoflife.date	2026-05-02	2026-05-21 23:35:01.495899	2026-05-21 23:35:01.495899
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
1	admin	Full administrative access. Interactive shell, command execution, file transfer, passwordless sudo. Added to wheel / sudo group (whichever exists on the host).	per_user	\N	["session_open", "command_exec", "file_transfer"]	f	f	900	3600	["wheel", "sudo"]	ALL=(ALL) NOPASSWD:ALL	t	2026-05-21 23:35:01.495899	2026-05-21 23:35:01.495899	90
2	maintainer	Fleet operator. Interactive shell, command execution, file transfer, passwordless sudo.	per_user	\N	["session_open", "command_exec", "file_transfer"]	f	f	900	3600	[]	ALL=(ALL) NOPASSWD:ALL	t	2026-05-21 23:35:01.495899	2026-05-21 23:35:01.495899	90
3	auditor	Read-only access. Interactive shell only. No command execution API, no file transfer, no sudo.	per_user	\N	["session_open"]	f	f	900	3600	[]	\N	t	2026-05-21 23:35:01.495899	2026-05-21 23:35:01.495899	90
\.


--
-- Data for Name: global_connection_settings; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.global_connection_settings (id, connection_timeout, max_pool_size, pool_cleanup_interval, max_idle_time, unreachable_threshold, default_ssh_port, created_at, updated_at) FROM stdin;
1	10	50	300	600	2	22	2026-05-21 23:35:01.495899	2026-05-21 23:35:01.495899
\.


--
-- Data for Name: groups; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.groups (id, name, description, parent_id, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: host_facts; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.host_facts (id, system_id, schema_version, collected_at, source_transport, cpu_model, cpu_cores, ram_total_bytes, kernel_version, distro_id_facts, distro_release, uptime_seconds, reboot_required, package_manager, package_manager_version, virtualization, cloud_provider, cloud_instance_metadata, disks, partial_errors, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: host_user_states; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.host_user_states (id, system_id, login, mode, state, last_error, last_reconciled_at, home_archive_path, created_at, updated_at) FROM stdin;
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
-- Data for Name: role; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.role (id, name, description, created_at, updated_at) FROM stdin;
\.


--
-- Data for Name: saved_views; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.saved_views (id, name, user_id, filters, is_default, is_shared, created_at, updated_at) FROM stdin;
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

COPY public.sessions (id, user_id, system_id, fleet_role_id, login, cert_serial, client_ip, status, close_reason, started_at, last_activity_at, ended_at, max_expires_at, created_at, updated_at, transport) FROM stdin;
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
1	300	\N	praxis-2f9e18b9c440	2026-05-21 23:35:01.495899	2026-05-21 23:35:01.495899
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

COPY public.system_metadata (id, system_id, cpu_arch, cpu_cores, memory_total, disk_total, environment_type, maintenance_window, owner_contact, location, ssh_port, last_connection, connection_status, created_at, updated_at, consecutive_failures) FROM stdin;
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
\.


--
-- Data for Name: user_role; Type: TABLE DATA; Schema: public; Owner: -
--

COPY public.user_role (user_id, role_id, created_at, updated_at) FROM stdin;
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

SELECT pg_catalog.setval('public.audit_events_id_seq', 1, false);


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

SELECT pg_catalog.setval('public.command_validation_rules_id_seq', 1, false);


--
-- Name: command_whitelist_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.command_whitelist_id_seq', 1, false);


--
-- Name: credentials_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.credentials_id_seq', 1, false);


--
-- Name: distro_lifecycle_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.distro_lifecycle_id_seq', 26, true);


--
-- Name: distro_lifecycle_override_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.distro_lifecycle_override_id_seq', 1, false);


--
-- Name: distros_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.distros_id_seq', 1, false);


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
-- Name: groups_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.groups_id_seq', 1, false);


--
-- Name: host_facts_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.host_facts_id_seq', 1, false);


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
-- Name: notification_preferences_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.notification_preferences_id_seq', 1, false);


--
-- Name: notifications_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.notifications_id_seq', 1, false);


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
-- Name: role_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.role_id_seq', 1, false);


--
-- Name: saved_views_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -
--

SELECT pg_catalog.setval('public.saved_views_id_seq', 1, false);


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

SELECT pg_catalog.setval('public.systems_id_seq', 1, false);


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

SELECT pg_catalog.setval('public.user_id_seq', 1, false);


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
-- Name: host_user_states uq_host_user_state_system_login; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.host_user_states
    ADD CONSTRAINT uq_host_user_state_system_login UNIQUE (system_id, login);


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
-- Name: ix_groups_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_groups_id ON public.groups USING btree (id);


--
-- Name: ix_groups_name; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ix_groups_name ON public.groups USING btree (name);


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
-- Name: groups groups_parent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.groups
    ADD CONSTRAINT groups_parent_id_fkey FOREIGN KEY (parent_id) REFERENCES public.groups(id) ON DELETE SET NULL;


--
-- Name: host_facts host_facts_system_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.host_facts
    ADD CONSTRAINT host_facts_system_id_fkey FOREIGN KEY (system_id) REFERENCES public.systems(id) ON DELETE CASCADE;


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

\unrestrict smdc9JJbYQ1coeqGtM2pUyJcoiiSPMJpzpOEzds1wNcoXC6oyiyo3ck42mKRI07


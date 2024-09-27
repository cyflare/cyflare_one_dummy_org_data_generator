import uuid
from dataclasses import InitVar, dataclass, field
from datetime import datetime, timedelta, timezone
from decimal import Decimal

from faker import Faker

from db import PostgreSQLClient
from faker_custom_provider import CustomProvider
from settings import DEFAULT_CUSTOMER_NAME

faker = Faker()
faker.add_provider(CustomProvider)


@dataclass
class Ticket:
    db_client: InitVar[PostgreSQLClient | None] = None
    datetime_for_create: InitVar[datetime | None] = None

    id: str = None
    department: str = field(default_factory=lambda: str(faker.random_number(digits=18)))
    department_name: str = field(default_factory=lambda: faker.department_name())
    contact_id: str = field(default_factory=lambda: str(faker.random_number(digits=18)))
    email: str = field(default_factory=lambda: faker.email())
    phone: str = field(default_factory=lambda: faker.basic_phone_number())
    contact_name: str = field(default_factory=lambda: faker.name())
    subject: str = field(
        default_factory=lambda: faker.sentence(
            ext_word_list=CustomProvider.subject_word_list,
            nb_words=2,
            variable_nb_words=False,
        )
    )
    ticket_status: str = field(default_factory=lambda: faker.ticket_status())
    ticket_owner: str = field(
        default_factory=lambda: str(faker.random_number(digits=18))
    )
    ticket_owner_name: str = field(default_factory=lambda: faker.name())
    created_time: datetime = None
    product_id: str = field(default_factory=lambda: str(faker.random_number(digits=18)))
    modified_time: datetime = None
    request_id: str = field(
        default_factory=lambda: str(faker.random_int(min=0, max=9999))
    )
    due_date: datetime = None
    priority: str = field(default_factory=lambda: faker.priority())
    channel: str = field(default_factory=lambda: faker.channel())
    to_address: str = field(default_factory=lambda: faker.email())
    customer_response_time: datetime = None
    number_of_threads: int = field(
        default_factory=lambda: faker.random_int(min=0, max=999)
    )
    category: str = field(default_factory=lambda: faker.category())
    sub_category: str = field(default_factory=lambda: faker.sub_category())
    is_escalated: str = field(default_factory=lambda: faker.yes_no())
    created_by: str = field(default_factory=lambda: str(faker.random_number(digits=18)))
    classifications: str = field(default_factory=lambda: faker.classifications())
    status_updated_time: datetime = field(
        default_factory=lambda: faker.date_time_this_month(
            after_now=True, tzinfo=timezone.utc
        )
    )
    ticket_closed_time: datetime = None
    modified_by: str = field(
        default_factory=lambda: str(faker.random_number(digits=18))
    )
    request_reopen_time: datetime = field(
        default_factory=lambda: faker.date_time_this_year(
            after_now=True, tzinfo=timezone.utc
        )
    )
    assigned_time: datetime = None
    first_assigned_time: datetime = None
    resolution: str = field(default_factory=lambda: faker.resolution())
    happiness_rating: str = field(default_factory=lambda: faker.happiness_rating())
    agent_responded_time: datetime = None
    number_of_comments: int = field(
        default_factory=lambda: faker.random_int(min=0, max=99)
    )
    resolution_time_in_business_hours: int = field(
        default_factory=lambda: faker.random_int(min=0, max=999999999)
    )
    first_response_time_in_business_hours: int = field(
        default_factory=lambda: faker.random_int(min=0, max=99999)
    )
    total_response_time_in_business_hours: int = field(
        default_factory=lambda: faker.random_int(min=0, max=99999)
    )
    number_of_responses: int = field(
        default_factory=lambda: faker.random_int(min=0, max=99)
    )
    number_of_outgoing: int = field(
        default_factory=lambda: faker.random_int(min=0, max=99)
    )
    number_of_reassign: int = field(
        default_factory=lambda: faker.random_int(min=0, max=99)
    )
    number_of_reopen: int = field(
        default_factory=lambda: faker.random_int(min=0, max=99)
    )
    ticket_age_in_days: int = field(
        default_factory=lambda: faker.random_int(min=1, max=99999)
    )
    assign_time_hrs: int = field(
        default_factory=lambda: faker.random_int(min=1, max=99999)
    )
    shift_ticket_creation: str = field(
        default_factory=lambda: faker.shift_ticket_creation()
    )
    ticket_touches: str = field(default_factory=lambda: faker.ticket_touches())
    status_group: str = field(default_factory=lambda: faker.status())
    ticket_age_tier: str = field(default_factory=lambda: faker.age_tier())
    requester_wait_time_hrs: Decimal = field(
        default_factory=lambda: faker.pydecimal(
            min_value=0, max_value=9999, right_digits=10
        )
    )
    first_reply_time_hrs: Decimal = field(
        default_factory=lambda: faker.pydecimal(
            min_value=0, max_value=9999, right_digits=10
        )
    )
    first_reply_time_age_tier: str = field(
        default_factory=lambda: faker.first_reply_age_tier()
    )
    resolution_time: Decimal = field(
        default_factory=lambda: faker.pydecimal(
            min_value=0, max_value=9999, right_digits=10
        )
    )
    completion_age_tier: str = field(
        default_factory=lambda: faker.completion_age_tier()
    )
    ticket_handling_mode: str = field(
        default_factory=lambda: faker.ticket_handling_mode()
    )
    is_first_call_resolution: str = field(default_factory=lambda: faker.yes_no())
    assignee_stations: int = field(
        default_factory=lambda: faker.random_int(min=0, max=99)
    )
    absolute_resolution_time: int = field(
        default_factory=lambda: faker.random_int(min=0, max=9999)
    )
    description: str = field(
        default_factory=lambda: faker.sentence(
            ext_word_list=CustomProvider.subject_word_list,
            nb_words=5,
            variable_nb_words=False,
        )
    )
    time_to_respond: datetime = None
    sla_name: str = field(default_factory=lambda: faker.sla_name())
    sla_violation_type: str = field(default_factory=lambda: faker.sla_violation_type())
    cyflare_incident_notification: str = field(
        default_factory=lambda: faker.cyflare_incident_notification()
    )
    source_ip_address_hostname_mac: str = field(default_factory=lambda: faker.ipv4())
    destination_ip_address_hostname_mac: str = field(
        default_factory=lambda: faker.ipv4()
    )
    incident_severity: str = field(default_factory=lambda: faker.severity())
    time_of_security_incident: datetime = None
    related_resources: str = field(default_factory=lambda: faker.url())
    associated_indicators_of_compromise: str = field(
        default_factory=lambda: faker.associated_indicators_of_compromise()
    )
    critical_asset: str = field(default_factory=lambda: faker.yes_no())
    ticket_create_time: datetime = None
    incident_summary: str = None
    recommended_remediation_actions: str = field(
        default_factory=lambda: faker.recommended_remediation_actions()
    )
    datediff: int = field(default_factory=lambda: faker.random_int(min=0, max=99))
    issue_type: str = field(default_factory=lambda: faker.issue_type())
    team_id: str = field(default_factory=lambda: str(faker.random_number(digits=18)))
    severity: str = field(default_factory=lambda: faker.severity())
    method: str = field(default_factory=lambda: faker.method())
    customer: str = DEFAULT_CUSTOMER_NAME
    mean_time_to_resolve: int = field(
        default_factory=lambda: faker.random_int(min=0, max=99999)
    )
    ticket_type: str = field(default_factory=lambda: faker.ticket_type())
    ticket_source: str = field(default_factory=lambda: faker.ticket_source())
    tickets_final_outcome_result: str = field(
        default_factory=lambda: faker.ticket_final_outcome_result()
    )

    def __post_init__(self, db_client, datetime_for_create):
        latest_ticket_id = db_client.get_latest_ticket_id()
        self.id = str(
            faker.random_int(
                min=latest_ticket_id + 100000000, max=latest_ticket_id + 1000000000
            )
        )

        self.created_time = datetime_for_create - timedelta(
            minutes=faker.random_int(1, 120)
        )
        self.time_of_security_incident = self.created_time - timedelta(
            minutes=faker.random_int(1, 120)
        )
        self.ticket_create_time = self.created_time
        self.assigned_time = self.created_time + timedelta(
            minutes=faker.random_int(1, 120)
        )
        self.first_assigned_time = self.assigned_time
        self.time_to_respond = self.assigned_time
        self.agent_responded_time = self.assigned_time + timedelta(
            minutes=faker.random_int(1, 30)
        )
        self.customer_response_time = self.agent_responded_time + timedelta(
            minutes=faker.random_int(1, 60)
        )

        self.due_date = self.created_time + timedelta(hours=faker.random_int(1, 60))
        self.ticket_closed_time = self.created_time + timedelta(
            hours=faker.random_int(1, 15)
        )
        self.modified_time = self.ticket_closed_time


@dataclass
class AlertStat:
    datetime_for_create: InitVar[datetime | None] = None

    tracking_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    case_id: int = field(default_factory=lambda: faker.random_number(digits=8))
    case_created_on: datetime = None
    case_source: str = field(default_factory=lambda: faker.case_source())
    customer: str = DEFAULT_CUSTOMER_NAME
    case_closed_on: datetime = None
    event_name: str = field(default_factory=lambda: faker.event_name())
    case_severity: str = field(default_factory=lambda: faker.severity())
    closure_reason: str = field(default_factory=lambda: faker.closure_reason())
    sla_exceeded: str = field(default_factory=lambda: faker.yes_no())
    sla_elapsed_minutes: int = field(
        default_factory=lambda: faker.random_int(min=0, max=99999)
    )
    case_status: str = field(default_factory=lambda: faker.case_status())
    username: str = field(default_factory=lambda: faker.username())
    alert_received_on: datetime = None
    sla_minutes: int = field(default_factory=lambda: faker.random_int(min=0, max=99999))
    zoho_ticket_number: str = field(
        default_factory=lambda: str(faker.random_number(digits=6))
    )
    source_ip_country: str = field(default_factory=lambda: faker.country())
    destination_ip_country: str = field(default_factory=lambda: faker.country())
    day_of_case_created_on: str = field(default_factory=lambda: faker.day_of_week())
    close_reason_justification: str = field(
        default_factory=lambda: faker.closure_reason()
    )
    case_current_owner: str = "Administrator"
    zoho_created_time: datetime = None
    category: str = None
    sub_category: str = None
    ti_reputation: str = field(default_factory=lambda: faker.ti_reputation())
    case_tag: str = field(default_factory=lambda: faker.case_tag())
    sip_reputation: str = field(default_factory=lambda: faker.sip_dip_reputation())
    dip_reputation: str = field(default_factory=lambda: faker.sip_dip_reputation())
    case_responded_on: datetime = None
    case_closed_by: str = "Administrator"
    destination_ip_type: str = field(default_factory=lambda: faker.ip_type())
    source_ip_type: str = field(default_factory=lambda: faker.ip_type())
    case_time_worked_min: int = field(
        default_factory=lambda: faker.random_int(min=0, max=9999)
    )
    case_time_worked: str = field(
        default_factory=lambda: faker.time(pattern="%-H:%M:%S.%f")
    )
    source_ip_region: str = None
    destination_ip_region: str = None
    source_ip_city: str = None
    destination_ip_city: str = None
    source_ip_latitude: str = None
    destination_ip_latitude: str = None
    source_ip_longitude: str = None
    destination_ip_longitude: str = None
    mitre_technique_name: str = field(
        default_factory=lambda: faker.mitre_technique_name()
    )
    mitre_sub_technique_name: str = field(
        default_factory=lambda: faker.mitre_sub_technique_name()
    )
    mitre_tactic: str = field(default_factory=lambda: faker.mitre_tactic())
    mitre_technique_id: str = field(default_factory=lambda: faker.mitre_technique_id())
    mitre_sub_technique_id: str = None
    mitre_tactic_id: str = field(default_factory=lambda: faker.mitre_tactic_id())
    last_escalated_tier: str = None
    event_occurred_on: datetime = None
    case_tt_claimed: str = None
    case_tt_closed: str = None
    source_ip: str = field(default_factory=lambda: faker.ip_address())
    destination_ip: str = field(default_factory=lambda: faker.ip_address())
    indicators: str = field(default_factory=lambda: faker.ipv4())
    case_tt_claimed_min: int = None
    case_tt_closed_min: int = field(
        default_factory=lambda: faker.random_int(min=0, max=9999)
    )
    source_ip_country_code: str = field(
        default_factory=lambda: faker.custom_country_code()
    )
    destination_ip_country_code: str = field(
        default_factory=lambda: faker.custom_country_code()
    )
    endpoint_name: str = field(default_factory=lambda: faker.hostname())
    s1_site_name: str = field(default_factory=lambda: faker.s1_site_name())
    s1_group_name: str = None
    xdr_event_category: str = field(default_factory=lambda: faker.xdr_event_category())
    xdr_msg_class: str = field(default_factory=lambda: faker.xdr_msg_class())
    xdr_msg_origin_source: str = field(
        default_factory=lambda: faker.xdr_msg_origin_source()
    )
    xdr_appid_name: str = field(default_factory=lambda: faker.xdr_appid_name())
    xdr_appid_family: str = field(default_factory=lambda: faker.xdr_appid_family())
    xdr_computer_name: str = field(default_factory=lambda: faker.hostname(0))
    xdr_domain_list: str = field(default_factory=lambda: faker.domain_name())
    xdr_dstip_reputation_source: str = field(
        default_factory=lambda: faker.xdr_dstip_reputation_source()
    )
    xdr_srcport: int = field(default_factory=lambda: faker.port_number())
    xdr_dstport: int = field(default_factory=lambda: faker.port_number())
    xdr_logon_process_name: str = field(
        default_factory=lambda: faker.xdr_logon_process_name()
    )
    xdr_logon_type: str = field(default_factory=lambda: faker.random_int(min=1, max=10))
    xdr_event_source: str = field(default_factory=lambda: faker.xdr_event_source())
    xdr_fim_action: str = field(default_factory=lambda: faker.xdr_fim_action())
    xdr_ids_category: str = field(default_factory=lambda: faker.xdr_ids_category())
    xdr_ids_cve: str = field(
        default_factory=lambda: str(
            f"CVE-{faker.year()}-{faker.random_int(min=0, max=9999)}"
        )
    )
    xdr_ids_severity: str = field(default_factory=lambda: faker.severity())
    xdr_ids_signature: str = field(default_factory=lambda: faker.xdr_ids_signature())
    xdr_login_type: str = field(default_factory=lambda: faker.xdr_login_type())

    def __post_init__(self, datetime_for_create):
        self.case_created_on = datetime_for_create - timedelta(
            minutes=faker.random_int(1, 120)
        )
        self.alert_received_on = self.case_created_on - timedelta(
            minutes=faker.random_int(1, 30)
        )
        self.zoho_created_time = self.case_created_on
        self.event_occurred_on = self.alert_received_on - timedelta(
            minutes=faker.random_int(1, 30)
        )
        self.case_responded_on = self.case_created_on + timedelta(
            minutes=faker.random_int(1, 120)
        )
        self.case_closed_on = self.case_created_on + timedelta(
            hours=faker.random_int(1, 15)
        )

        (
            self.source_ip_latitude,
            self.source_ip_longitude,
            self.source_ip_region,
            self.source_ip_country_code,
            ignore,
        ) = faker.local_latlng(self.source_ip_country_code)

        (
            self.destination_ip_latitude,
            self.destination_ip_longitude,
            self.destination_ip_region,
            self.destination_ip_country_code,
            ignore,
        ) = faker.local_latlng(self.destination_ip_country_code)


@dataclass
class XDRData:
    created_on: datetime = None
    organization: int = None
    tenant_id: str = None
    source: str = None
    customer: str = DEFAULT_CUSTOMER_NAME
    windows_sensors_expected: int = None
    windows_sensors_configured: int = None
    windows_sensors_connected: int = None
    windows_sensors_disconnected: int = None
    windows_sensors_data_ingested_bytes: int = None
    windows_sensors_data_ingested: str = None
    linux_sensors_expected: int = None
    linux_sensors_configured: int = None
    linux_sensors_connected: int = None
    linux_sensors_disconnected: int = None
    linux_sensors_data_ingested_bytes: int = None
    linux_sensors_data_ingested: str = None
    network_sensors_expected: int = None
    network_sensors_configured: int = None
    network_sensors_connected: int = None
    network_sensors_disconnected: int = None
    network_sensors_data_ingested_bytes: int = None
    network_sensors_data_ingested: str = None
    security_sensors_expected: int = None
    security_sensors_configured: int = None
    security_sensors_connected: int = None
    security_sensors_disconnected: int = None
    security_sensors_data_ingested_bytes: int = None
    security_sensors_data_ingested: str = None
    syslog_senders_expected: int = None
    syslog_senders_configured: int = None
    syslog_senders_connected: int = None
    syslog_senders_disconnected: int = None
    syslog_senders_data_ingested_bytes: int = None
    syslog_senders_data_ingested: str = None
    syslog_senders: str = None
    connectors_expected: int = None
    connectors_configured: int = None
    connectors_connected: int = None
    connectors_disconnected: int = None
    connectors_data_ingested_bytes: int = None
    connectors_data_ingested: str = None
    connectors_up: str = None
    connectors_down: str = None
    total_sensors_expected: int = None
    total_sensors_connected: int = None
    coverage_metric: Decimal = None
    total_data_ingested_bytes: int = None
    total_data_ingested: str = None
    assets_seen: int = None
    security_events: int = None


@dataclass
class XDRConnector:
    connector_name: str = None


@dataclass
class XDRConnectorStatus:
    xdr_id: XDRData = None
    xdr_connector: XDRConnector = None
    status: str = None
    timestamp: datetime = None


@dataclass
class SyslogSource:
    entity_identifier: str = None


@dataclass
class SyslogSourceStatus:
    xdr_id: XDRData = None
    syslog_source: SyslogSource = None
    source_ip: str = None
    port: int = None
    tenant_name: str = None
    cust_id: str = None
    total_ingestion: str = None
    timestamp: datetime = None

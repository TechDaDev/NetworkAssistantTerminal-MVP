from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class ScanRun(Base):
    __tablename__ = "scan_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    interface_name: Mapped[str] = mapped_column(String(100))
    local_ip: Mapped[str] = mapped_column(String(45))
    cidr: Mapped[str] = mapped_column(String(50))
    gateway_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    live_hosts_count: Mapped[int] = mapped_column(Integer, default=0)
    summary_json: Mapped[str] = mapped_column(Text, default="{}")


class Device(Base):
    __tablename__ = "devices"
    __table_args__ = (UniqueConstraint("ip_address", name="uq_devices_ip_address"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ip_address: Mapped[str] = mapped_column(String(45), index=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    mac_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    vendor_guess: Mapped[str] = mapped_column(String(100), default="Unknown")
    device_type_guess: Mapped[str] = mapped_column(String(100), default="Unknown")
    confidence: Mapped[str] = mapped_column(String(30), default="Low")
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

    ports: Mapped[list["DevicePort"]] = relationship(
        back_populates="device", cascade="all, delete-orphan"
    )
    facts: Mapped[list["NetworkFact"]] = relationship(
        back_populates="device", cascade="all, delete-orphan"
    )
    observations: Mapped[list["DeviceObservation"]] = relationship(
        back_populates="device", cascade="all, delete-orphan"
    )
    credentials: Mapped[list["DeviceCredential"]] = relationship(
        back_populates="device", cascade="all, delete-orphan"
    )
    command_runs: Mapped[list["CommandRun"]] = relationship(
        back_populates="device", cascade="all, delete-orphan"
    )
    config_snapshots: Mapped[list["DeviceConfigSnapshot"]] = relationship(
        back_populates="device", cascade="all, delete-orphan"
    )
    change_plans: Mapped[list["ChangePlan"]] = relationship(
        back_populates="device", cascade="all, delete-orphan"
    )
    execution_logs: Mapped[list["ExecutionLog"]] = relationship(
        back_populates="device", cascade="all, delete-orphan"
    )


class DevicePort(Base):
    __tablename__ = "device_ports"
    __table_args__ = (UniqueConstraint("device_id", "port", "protocol", name="uq_device_port"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"), index=True)
    port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(20), default="tcp")
    service_guess: Mapped[str] = mapped_column(String(100), default="Unknown")
    state: Mapped[str] = mapped_column(String(30), default="open")
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    device: Mapped[Device] = relationship(back_populates="ports")


class NetworkFact(Base):
    __tablename__ = "network_facts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"), index=True)
    fact_type: Mapped[str] = mapped_column(String(100))
    fact_value: Mapped[str] = mapped_column(Text)
    confidence: Mapped[str] = mapped_column(String(30), default="Low")
    source: Mapped[str] = mapped_column(String(100), default="scanner")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    device: Mapped[Device] = relationship(back_populates="facts")


class DeviceObservation(Base):
    __tablename__ = "device_observations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"), index=True)
    observation_type: Mapped[str] = mapped_column(String(100), index=True)
    observation_value: Mapped[str] = mapped_column(Text)
    source: Mapped[str] = mapped_column(String(100), default="enrichment")
    confidence: Mapped[str] = mapped_column(String(30), default="Low")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    device: Mapped[Device] = relationship(back_populates="observations")


class DeviceKnowledge(Base):
    __tablename__ = "device_knowledge"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    vendor: Mapped[str | None] = mapped_column(String(100), nullable=True, index=True)
    model: Mapped[str | None] = mapped_column(String(150), nullable=True, index=True)
    device_type: Mapped[str | None] = mapped_column(String(100), nullable=True, index=True)
    doc_type: Mapped[str] = mapped_column(String(100), default="vendor_note", index=True)
    tags: Mapped[str] = mapped_column(Text, default="")
    content_hash: Mapped[str] = mapped_column(String(64), default="", index=True)
    source_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_trusted: Mapped[bool] = mapped_column(Boolean, default=False)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    title: Mapped[str] = mapped_column(String(255))
    content: Mapped[str] = mapped_column(Text)
    source_type: Mapped[str] = mapped_column(String(100), default="manual")
    source_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)


class DeviceCredential(Base):
    __tablename__ = "device_credentials"
    __table_args__ = (UniqueConstraint("device_id", "connection_type", name="uq_device_connection_type"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"), index=True)
    username: Mapped[str] = mapped_column(String(255))
    encrypted_password: Mapped[str] = mapped_column(Text)
    connection_type: Mapped[str] = mapped_column(String(50), default="ssh")
    port: Mapped[int] = mapped_column(Integer, default=22)
    platform_hint: Mapped[str] = mapped_column(String(100), default="unknown_ssh")
    status: Mapped[str] = mapped_column(String(50), default="untested")
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

    device: Mapped[Device] = relationship(back_populates="credentials")


class CommandRun(Base):
    __tablename__ = "command_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"), index=True)
    command: Mapped[str] = mapped_column(String(255))
    output: Mapped[str] = mapped_column(Text, default="")
    success: Mapped[bool] = mapped_column(Boolean, default=False)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    finished_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    device: Mapped[Device] = relationship(back_populates="command_runs")


class DeviceConfigSnapshot(Base):
    __tablename__ = "device_config_snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"), index=True)
    plan_id: Mapped[int | None] = mapped_column(ForeignKey("change_plans.id"), index=True, nullable=True)
    execution_log_id: Mapped[int | None] = mapped_column(ForeignKey("execution_logs.id"), index=True, nullable=True)
    snapshot_type: Mapped[str] = mapped_column(String(100))
    platform: Mapped[str | None] = mapped_column(String(100), nullable=True)
    content: Mapped[str] = mapped_column(Text)
    command_outputs_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    device: Mapped[Device] = relationship(back_populates="config_snapshots")


class ChangePlan(Base):
    __tablename__ = "change_plans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"), index=True)
    plan_type: Mapped[str] = mapped_column(String(100), index=True)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text)
    risk_level: Mapped[str] = mapped_column(String(30), default="medium")
    status: Mapped[str] = mapped_column(String(30), default="draft")
    proposed_commands: Mapped[str] = mapped_column(Text)
    rollback_commands: Mapped[str] = mapped_column(Text)
    validation_findings: Mapped[str] = mapped_column(Text, default="[]")
    preflight_status: Mapped[str] = mapped_column(String(30), default="not_run")
    preflight_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    preflight_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

    device: Mapped[Device] = relationship(back_populates="change_plans")
    approval_logs: Mapped[list["ApprovalLog"]] = relationship(
        back_populates="plan", cascade="all, delete-orphan"
    )
    execution_logs: Mapped[list["ExecutionLog"]] = relationship(
        back_populates="plan", cascade="all, delete-orphan"
    )


class ApprovalLog(Base):
    __tablename__ = "approval_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    plan_id: Mapped[int] = mapped_column(ForeignKey("change_plans.id"), index=True)
    action: Mapped[str] = mapped_column(String(50))
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    plan: Mapped[ChangePlan] = relationship(back_populates="approval_logs")


class ExecutionLog(Base):
    __tablename__ = "execution_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    plan_id: Mapped[int] = mapped_column(ForeignKey("change_plans.id"), index=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"), index=True)
    status: Mapped[str] = mapped_column(String(50), default="started")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    pre_check_output: Mapped[str] = mapped_column(Text, default="")
    execution_output: Mapped[str] = mapped_column(Text, default="")
    post_check_output: Mapped[str] = mapped_column(Text, default="")
    rollback_output: Mapped[str] = mapped_column(Text, default="")
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    plan: Mapped[ChangePlan] = relationship(back_populates="execution_logs")
    device: Mapped[Device] = relationship(back_populates="execution_logs")


class AgentActionLog(Base):
    __tablename__ = "agent_action_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    session_id: Mapped[str] = mapped_column(String(80), index=True)
    user_input: Mapped[str] = mapped_column(Text)
    parsed_intent: Mapped[str] = mapped_column(Text, default="{}")
    tool_name: Mapped[str] = mapped_column(String(100), index=True)
    risk_level: Mapped[str] = mapped_column(String(30), default="unknown")
    policy_decision: Mapped[str] = mapped_column(Text, default="")
    confirmation_required: Mapped[bool] = mapped_column(Boolean, default=False)
    confirmation_result: Mapped[str] = mapped_column(String(30), default="not_required")
    executed: Mapped[bool] = mapped_column(Boolean, default=False)
    success: Mapped[bool] = mapped_column(Boolean, default=False)
    result_summary: Mapped[str] = mapped_column(Text, default="")
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class TopologySnapshot(Base):
    __tablename__ = "topology_snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(255))
    source: Mapped[str] = mapped_column(String(100), default="local_inventory")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    summary_json: Mapped[str] = mapped_column(Text, default="{}")

    nodes: Mapped[list["TopologyNode"]] = relationship(
        back_populates="snapshot", cascade="all, delete-orphan"
    )
    edges: Mapped[list["TopologyEdge"]] = relationship(
        back_populates="snapshot", cascade="all, delete-orphan"
    )


class TopologyNode(Base):
    __tablename__ = "topology_nodes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    snapshot_id: Mapped[int] = mapped_column(ForeignKey("topology_snapshots.id"), index=True)
    device_id: Mapped[int | None] = mapped_column(ForeignKey("devices.id"), nullable=True, index=True)
    node_key: Mapped[str] = mapped_column(String(255), index=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    mac_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    label: Mapped[str] = mapped_column(String(255))
    node_type: Mapped[str] = mapped_column(String(50), default="unknown")
    vendor: Mapped[str] = mapped_column(String(100), default="Unknown")
    confidence: Mapped[str] = mapped_column(String(30), default="low")
    evidence: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    snapshot: Mapped[TopologySnapshot] = relationship(back_populates="nodes")
    device: Mapped[Device | None] = relationship()


class TopologyEdge(Base):
    __tablename__ = "topology_edges"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    snapshot_id: Mapped[int] = mapped_column(ForeignKey("topology_snapshots.id"), index=True)
    source_node_key: Mapped[str] = mapped_column(String(255), index=True)
    target_node_key: Mapped[str] = mapped_column(String(255), index=True)
    relation_type: Mapped[str] = mapped_column(String(50))
    confidence: Mapped[str] = mapped_column(String(30), default="low")
    evidence_source: Mapped[str] = mapped_column(String(100))
    evidence: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    snapshot: Mapped[TopologySnapshot] = relationship(back_populates="edges")


class ManualTopologyNode(Base):
    __tablename__ = "manual_topology_nodes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    node_key: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    label: Mapped[str] = mapped_column(String(80))
    node_type: Mapped[str] = mapped_column(String(50), default="unknown")
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    mac_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    vendor: Mapped[str | None] = mapped_column(String(100), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)


class ManualTopologyEdge(Base):
    __tablename__ = "manual_topology_edges"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source_node_key: Mapped[str] = mapped_column(String(255), index=True)
    target_node_key: Mapped[str] = mapped_column(String(255), index=True)
    relation_type: Mapped[str] = mapped_column(String(50), default="manual")
    label: Mapped[str | None] = mapped_column(String(80), nullable=True)
    confidence: Mapped[str] = mapped_column(String(30), default="high")
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)


class ManualTopologyNote(Base):
    __tablename__ = "manual_topology_notes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_type: Mapped[str] = mapped_column(String(30))
    target_key: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    note: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)

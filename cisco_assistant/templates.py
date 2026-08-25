"""Versioned offline network templates.

Templates translate beginner-friendly parameters into normalized ``NetworkIntent`` objects.
They never emit CLI, open sockets, or gain device execution authority.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .ipam import GatewayStrategy, generate_sequential_networks, subnet_facts
from .models import (
    ManagementIntent,
    ModelValidationError,
    NetworkIntent,
    PortIntent,
    RoutingIntent,
    SecurityIntent,
    SecurityProfile,
    UplinkIntent,
    VLANIntent,
)
from .validation import ValidationResult, validate_network_intent


TEMPLATE_SCHEMA_VERSION = 1


class TemplateError(ModelValidationError):
    """Raised when template parameters cannot produce a safe normalized intent."""


class TemplateId(str, Enum):
    SMALL_OFFICE = "small_office"
    OFFICE_IP_CAMERAS = "office_ip_cameras"
    AI_CAMERA_VMS = "ai_camera_vms"


@dataclass(frozen=True, slots=True)
class TemplateRole:
    key: str
    display_name: str
    vlan_name: str
    purpose: str
    assignable_access_ports: bool = True


@dataclass(frozen=True, slots=True)
class TemplateDefinition:
    template_id: TemplateId
    version: str
    display_name: str
    description: str
    roles: tuple[TemplateRole, ...]
    assumptions: tuple[str, ...] = field(default_factory=tuple)
    schema_version: int = TEMPLATE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != TEMPLATE_SCHEMA_VERSION:
            raise TemplateError(
                f"Unsupported template schema version {self.schema_version}; "
                f"expected {TEMPLATE_SCHEMA_VERSION}"
            )
        if not self.version.strip():
            raise TemplateError("template version must not be empty")
        if not self.display_name.strip():
            raise TemplateError("template display_name must not be empty")
        if not self.roles:
            raise TemplateError("template must define at least one role")
        role_keys = [role.key for role in self.roles]
        if len(role_keys) != len(set(role_keys)):
            raise TemplateError(f"duplicate role keys in template {self.template_id.value}")
        if "management" not in role_keys:
            raise TemplateError("every initial production template requires a management role")

    @property
    def role_keys(self) -> tuple[str, ...]:
        return tuple(role.key for role in self.roles)


@dataclass(frozen=True, slots=True)
class RolePortCount:
    role: str
    count: int

    def __post_init__(self) -> None:
        role = self.role.strip().lower()
        if not role:
            raise TemplateError("role must not be empty")
        if self.count < 0:
            raise TemplateError("port count must not be negative")
        object.__setattr__(self, "role", role)


@dataclass(frozen=True, slots=True)
class TemplateRequest:
    """User/site parameters shared by the first guided templates.

    ``access_interfaces`` is intentionally provided by inventory/UI instead of generated from
    an assumed Cisco interface naming convention. This keeps the template engine device-neutral
    and lets the capability/inventory layer remain authoritative for physical port identity.
    """

    template_id: TemplateId | str
    site_name: str
    start_vlan_id: int
    start_network: str
    vlan_increment: int = 10
    gateway_strategy: GatewayStrategy | str = GatewayStrategy.FIRST_USABLE
    security_profile: SecurityProfile | str = SecurityProfile.BUSINESS_STANDARD
    role_port_counts: tuple[RolePortCount, ...] = field(default_factory=tuple)
    access_interfaces: tuple[str, ...] = field(default_factory=tuple)
    uplink_interface: str | None = None
    management_source_networks: tuple[str, ...] = field(default_factory=tuple)
    inter_vlan_routing: bool = False

    def __post_init__(self) -> None:
        try:
            template_id = (
                self.template_id
                if isinstance(self.template_id, TemplateId)
                else TemplateId(self.template_id)
            )
        except ValueError as exc:
            raise TemplateError(f"Unknown template_id {self.template_id!r}") from exc
        object.__setattr__(self, "template_id", template_id)

        site_name = self.site_name.strip()
        if not site_name:
            raise TemplateError("site_name must not be empty")
        object.__setattr__(self, "site_name", site_name)

        if not 1 <= self.start_vlan_id <= 4094:
            raise TemplateError("start_vlan_id must be inside 1..4094")
        if self.vlan_increment <= 0:
            raise TemplateError("vlan_increment must be greater than zero")

        try:
            gateway_strategy = (
                self.gateway_strategy
                if isinstance(self.gateway_strategy, GatewayStrategy)
                else GatewayStrategy(self.gateway_strategy)
            )
        except ValueError as exc:
            raise TemplateError(
                f"Unsupported gateway strategy {self.gateway_strategy!r}"
            ) from exc
        object.__setattr__(self, "gateway_strategy", gateway_strategy)

        try:
            security_profile = (
                self.security_profile
                if isinstance(self.security_profile, SecurityProfile)
                else SecurityProfile(self.security_profile)
            )
        except ValueError as exc:
            raise TemplateError(
                f"Unsupported security profile {self.security_profile!r}"
            ) from exc
        object.__setattr__(self, "security_profile", security_profile)

        counts = tuple(self.role_port_counts)
        seen_roles: set[str] = set()
        for item in counts:
            if item.role in seen_roles:
                raise TemplateError(f"Duplicate role_port_counts entry for {item.role!r}")
            seen_roles.add(item.role)
        object.__setattr__(self, "role_port_counts", counts)

        interfaces = tuple(value.strip() for value in self.access_interfaces)
        if any(not value for value in interfaces):
            raise TemplateError("access_interfaces cannot contain empty names")
        folded = [value.casefold() for value in interfaces]
        if len(folded) != len(set(folded)):
            raise TemplateError("access_interfaces contains duplicate interface names")
        object.__setattr__(self, "access_interfaces", interfaces)

        if self.uplink_interface is not None:
            uplink = self.uplink_interface.strip()
            if not uplink:
                raise TemplateError("uplink_interface must not be empty when provided")
            if uplink.casefold() in set(folded):
                raise TemplateError(
                    "uplink_interface must not also appear in access_interfaces"
                )
            object.__setattr__(self, "uplink_interface", uplink)

        object.__setattr__(
            self,
            "management_source_networks",
            tuple(self.management_source_networks),
        )


@dataclass(frozen=True, slots=True)
class TemplateBuildResult:
    definition: TemplateDefinition
    request: TemplateRequest
    intent: NetworkIntent
    validation: ValidationResult
    unassigned_interfaces: tuple[str, ...]
    notes: tuple[str, ...]


TEMPLATE_REGISTRY: dict[TemplateId, TemplateDefinition] = {
    TemplateId.SMALL_OFFICE: TemplateDefinition(
        template_id=TemplateId.SMALL_OFFICE,
        version="1.0.0",
        display_name="Small Office",
        description=(
            "Dedicated management, office-user, and guest segments for a small office."
        ),
        roles=(
            TemplateRole(
                "management",
                "Management",
                "MGMT",
                "management",
                assignable_access_ports=False,
            ),
            TemplateRole("office", "Office", "OFFICE", "office"),
            TemplateRole("guest", "Guest", "GUEST", "guest"),
        ),
        assumptions=(
            "Management is modeled as a dedicated VLAN.",
            "Guest isolation policy is expressed later by the security/segmentation planner.",
            "No routing placement is assumed unless inter_vlan_routing is explicitly requested.",
        ),
    ),
    TemplateId.OFFICE_IP_CAMERAS: TemplateDefinition(
        template_id=TemplateId.OFFICE_IP_CAMERAS,
        version="1.0.0",
        display_name="Office + IP Cameras",
        description=(
            "Dedicated management, office-user, and IP-camera segments for mixed office/video sites."
        ),
        roles=(
            TemplateRole(
                "management",
                "Management",
                "MGMT",
                "management",
                assignable_access_ports=False,
            ),
            TemplateRole("office", "Office", "OFFICE", "office"),
            TemplateRole("camera", "IP Cameras", "CAMERA", "camera"),
        ),
        assumptions=(
            "Camera/office reachability is not silently granted; segmentation is a later explicit policy decision.",
            "No Internet policy is inferred from the template alone.",
            "No routing placement is assumed unless inter_vlan_routing is explicitly requested.",
        ),
    ),
    TemplateId.AI_CAMERA_VMS: TemplateDefinition(
        template_id=TemplateId.AI_CAMERA_VMS,
        version="1.0.0",
        display_name="AI Camera / VMS",
        description=(
            "Dedicated management, camera, AI-server, and VMS segments for video analytics deployments."
        ),
        roles=(
            TemplateRole(
                "management",
                "Management",
                "MGMT",
                "management",
                assignable_access_ports=False,
            ),
            TemplateRole("camera", "IP Cameras", "CAMERA", "camera"),
            TemplateRole("ai_server", "AI Servers", "AI_SERVER", "ai_server"),
            TemplateRole("vms", "VMS", "VMS", "vms"),
        ),
        assumptions=(
            "Camera, AI-server, and VMS communication policy is not guessed by the template.",
            "Bandwidth/QoS sizing remains a separate explicit design step.",
            "No routing placement is assumed unless inter_vlan_routing is explicitly requested.",
        ),
    ),
}


def list_templates() -> tuple[TemplateDefinition, ...]:
    return tuple(TEMPLATE_REGISTRY[template_id] for template_id in TemplateId)


def get_template_definition(template_id: TemplateId | str) -> TemplateDefinition:
    try:
        normalized = template_id if isinstance(template_id, TemplateId) else TemplateId(template_id)
    except ValueError as exc:
        raise TemplateError(f"Unknown template_id {template_id!r}") from exc
    return TEMPLATE_REGISTRY[normalized]


def _build_vlans(
    definition: TemplateDefinition,
    request: TemplateRequest,
) -> tuple[VLANIntent, ...]:
    count = len(definition.roles)
    vlan_ids = tuple(
        request.start_vlan_id + (index * request.vlan_increment)
        for index in range(count)
    )
    if any(vlan_id > 4094 for vlan_id in vlan_ids):
        raise TemplateError(
            f"Template VLAN sequence exceeds 4094: first={vlan_ids[0]}, last={vlan_ids[-1]}"
        )

    networks = generate_sequential_networks(request.start_network, count)
    vlans: list[VLANIntent] = []
    for role, vlan_id, network in zip(definition.roles, vlan_ids, networks, strict=True):
        facts = subnet_facts(
            str(network),
            gateway_strategy=request.gateway_strategy,
        )
        vlans.append(
            VLANIntent(
                id=vlan_id,
                name=role.vlan_name,
                network=facts.network,
                gateway=facts.gateway,
                purpose=role.purpose,
            )
        )
    return tuple(vlans)


def _allocate_access_ports(
    definition: TemplateDefinition,
    request: TemplateRequest,
    role_to_vlan: dict[str, int],
) -> tuple[tuple[PortIntent, ...], tuple[str, ...]]:
    role_by_key = {role.key: role for role in definition.roles}
    requested_counts = {item.role: item.count for item in request.role_port_counts}

    unknown = set(requested_counts) - set(role_by_key)
    if unknown:
        raise TemplateError(
            f"Template {definition.template_id.value} does not define roles {sorted(unknown)}"
        )

    non_assignable = {
        role_key
        for role_key, count in requested_counts.items()
        if count > 0 and not role_by_key[role_key].assignable_access_ports
    }
    if non_assignable:
        raise TemplateError(
            f"Roles {sorted(non_assignable)} are not access-port assignable in this template"
        )

    requested_total = sum(requested_counts.values())
    if requested_total > len(request.access_interfaces):
        raise TemplateError(
            f"Requested {requested_total} access ports but only "
            f"{len(request.access_interfaces)} interfaces were supplied"
        )

    ports: list[PortIntent] = []
    cursor = 0
    # Allocate in template role order, not request order, for reproducible output.
    for role in definition.roles:
        count = requested_counts.get(role.key, 0)
        for interface in request.access_interfaces[cursor : cursor + count]:
            ports.append(
                PortIntent(
                    interface=interface,
                    role=role.key,
                    mode="access",
                    access_vlan=role_to_vlan[role.key],
                )
            )
        cursor += count

    return tuple(ports), request.access_interfaces[cursor:]


def build_template(request: TemplateRequest) -> TemplateBuildResult:
    """Compile a versioned template into normalized intent and offline validation only."""
    definition = get_template_definition(request.template_id)
    vlans = _build_vlans(definition, request)
    role_to_vlan = {
        role.key: vlan.id for role, vlan in zip(definition.roles, vlans, strict=True)
    }

    ports, unassigned = _allocate_access_ports(definition, request, role_to_vlan)

    uplinks: tuple[UplinkIntent, ...] = ()
    if request.uplink_interface is not None:
        uplinks = (
            UplinkIntent(
                interface=request.uplink_interface,
                allowed_vlans=tuple(vlan.id for vlan in vlans),
            ),
        )

    management = ManagementIntent(
        vlan_id=role_to_vlan["management"],
        allowed_source_networks=request.management_source_networks,
        services=("ssh", "https"),
        require_dedicated_vlan=True,
    )

    intent = NetworkIntent(
        site_name=request.site_name,
        vlans=vlans,
        ports=ports,
        uplinks=uplinks,
        routing=RoutingIntent(inter_vlan_routing=request.inter_vlan_routing),
        management=management,
        security_profile=request.security_profile,
        security=SecurityIntent(profile=request.security_profile),
        template=f"{definition.template_id.value}@{definition.version}",
    )

    validation = validate_network_intent(intent)
    notes = list(definition.assumptions)
    if request.uplink_interface is None:
        notes.append(
            "No uplink is declared yet; a later topology step must identify how required VLANs leave this switch."
        )
    if not request.management_source_networks:
        notes.append(
            "Management source networks are not declared; future management lockout analysis cannot be completed."
        )

    return TemplateBuildResult(
        definition=definition,
        request=request,
        intent=intent,
        validation=validation,
        unassigned_interfaces=tuple(unassigned),
        notes=tuple(notes),
    )

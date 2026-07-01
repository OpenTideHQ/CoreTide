import git
import sys
import json
from typing import Sequence

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.splunk import (
    SplunkEngineInit,
    connect_splunk,
    cron_to_timeframe,
    create_query_v4,
    splunk_timerange,
)
from Engines.modules.framework import (
    techniques_resolver,
)
from Engines.modules.logs import log
from Engines.modules.debug import DebugEnvironment
from Engines.modules.tide import DataTide, DetectionSystems
from Engines.modules.models import (
    StatusStrategy,
    TideModels,
    TideConfigs,
    TenantDeployment,
    DeploymentStrategy,
)
from Engines.modules.deployment import check_status, TideDeployment
from Engines.modules.plugins import DeployMDR


class SplunkDeploy(SplunkEngineInit, DeployMDR):

    # ─── Configuration builder ────────────────────────────────────────

    def _should_enable_correlation_search(
        self,
        tenant_setup: TideConfigs.Systems.Splunk.Tenant.Setup,
        mdr_config: TideModels.MDR.Configurations.Splunk,
    ) -> bool:
        """Determine whether this MDR should be deployed as a correlation search.

        Resolution order:
        1. Per-MDR ``correlation_search`` field (explicit override) wins if set
        2. Tenant-level ``enterprise_security`` flag (from TOML setup)
        3. Global ``CORRELATION_SEARCHES`` from legacy init (fallback)
        """
        if mdr_config.correlation_search is not None:
            return mdr_config.correlation_search
        if hasattr(tenant_setup, "enterprise_security"):
            return tenant_setup.enterprise_security
        return self.CORRELATION_SEARCHES

    def _is_action_allowed(
        self,
        action: str,
        tenant_setup: TideConfigs.Systems.Splunk.Tenant.Setup,
    ) -> bool:
        """Check whether an ES-gated action (notable/risk) is allowed for this tenant."""
        es_enabled = getattr(tenant_setup, "enterprise_security", False)
        if action in ("notable", "risk"):
            return es_enabled
        return True

    def config_mdr(
        self,
        data: TideModels.MDR,
        tenant_setup: TideConfigs.Systems.Splunk.Tenant.Setup,
    ) -> dict:
        """Build the savedsearches.conf attribute dict from a typed MDR object.

        Translates the typed MDR Splunk configuration into a flat dictionary of
        Splunk saved search attributes ready for deployment via splunklib.

        Modifiers are resolved centrally by TideDeployment.modifiers_resolver()
        before this method is called — the MDR object received here already
        incorporates all modifier transformations.
        """
        config: dict = {}

        splunk_config = data.configurations.splunk
        if not splunk_config:
            raise Exception("Missing Splunk configuration in MDR")

        name = data.name.strip()
        uuid = data.metadata.uuid

        # ── Scheduling ────────────────────────────────────────────────
        if splunk_config.scheduling:
            sched = splunk_config.scheduling

            if sched.type:
                if sched.type.lower() == "real time":
                    config["dispatch.earliest_time"] = "rt"
                    config["dispatch.latest_time"] = "rt"
                else:
                    config["is_scheduled"] = 1

            if sched.expires:
                config["alert.expires"] = sched.expires

            if sched.schedule:
                schedule = sched.schedule
                if schedule.cron:
                    config["cron_schedule"] = schedule.cron
                elif schedule.frequency:
                    custom_time = schedule.custom_time
                    if custom_time:
                        config["cron_schedule"] = cron_to_timeframe(
                            schedule.frequency, mode="custom", custom_time=custom_time
                        )
                    else:
                        config["cron_schedule"] = cron_to_timeframe(
                            schedule.frequency, mode=self.TIMERANGE_MODE
                        )

            if sched.timerange:
                tr = sched.timerange
                if tr.lookback:
                    config["dispatch.earliest_time"] = splunk_timerange(
                        tr.lookback, skewing=self.SKEWING_VALUE, offset=self.OFFSET
                    )
                if tr.earliest:
                    config["dispatch.earliest_time"] = tr.earliest
                if tr.latest:
                    config["dispatch.latest_time"] = tr.latest

        # ── Trigger ───────────────────────────────────────────────────
        if splunk_config.trigger:
            trig = splunk_config.trigger

            if trig.condition:
                config["counttype"] = trig.condition
            if trig.comparator:
                config["relation"] = trig.comparator
            if trig.threshold is not None:
                config["quantity"] = trig.threshold
            if trig.severity is not None:
                config["alert.severity"] = trig.severity
            if trig.custom_condition:
                config["alert_condition"] = trig.custom_condition
            if trig.type:
                config["alert.digest_mode"] = (
                    "true" if trig.type.lower() == "once" else "false"
                )

            if trig.throttling:
                throt = trig.throttling
                if throt.duration:
                    config["alert.suppress.period"] = throt.duration
                    config["alert.suppress"] = "true"
                if throt.fields:
                    config["alert.suppress.fields"] = ", ".join(throt.fields)
                if throt.group_name:
                    config["alert.suppress.group_name"] = throt.group_name

        # ── Alert Severity from response (fallback if not in trigger) ─
        if "alert.severity" not in config:
            alert_severity = getattr(data.response, "alert_severity", None)
            if alert_severity:
                config["alert.severity"] = self.ALERT_SEVERITY_MAPPING.get(
                    alert_severity, 3
                )

        # ── Status / Disabled ─────────────────────────────────────────
        if check_status(splunk_config.status) is StatusStrategy.DISABLEMENT:
            config["disabled"] = "true"
            log("INFO", "Configuring saved search as disabled")

        # ── Correlation search setup ──────────────────────────────────
        enable_correlation = self._should_enable_correlation_search(
            tenant_setup, splunk_config
        )
        if enable_correlation:
            config["action.correlationsearch.enabled"] = "true"
            config["action.correlationsearch.label"] = name + " - Rule"
            techniques = techniques_resolver(uuid)
            if techniques:
                config[
                    "action.correlationsearch.annotations.mitre_attack"
                ] = ", ".join(techniques)

        # ── Actions ───────────────────────────────────────────────────
        if splunk_config.actions:
            acts = splunk_config.actions

            # Notable
            if acts.notable and self._is_action_allowed("notable", tenant_setup):
                notable = acts.notable
                if notable.event:
                    if notable.event.title:
                        config["action.notable.param.rule_title"] = notable.event.title
                    if notable.event.description:
                        config[
                            "action.notable.param.rule_description"
                        ] = notable.event.description
                if notable.drilldown:
                    if notable.drilldown.name:
                        config[
                            "action.notable.param.drilldown_name"
                        ] = notable.drilldown.name
                    if notable.drilldown.search:
                        config[
                            "action.notable.param.drilldown_search"
                        ] = notable.drilldown.search
                if notable.security_domain:
                    config[
                        "action.notable.param.security_domain"
                    ] = notable.security_domain.lower()

            # Risk
            if acts.risk and self._is_action_allowed("risk", tenant_setup):
                risk = acts.risk
                risk_config_list = []

                if risk.risk_objects:
                    for ro in risk.risk_objects:
                        risk_config_list.append(
                            {
                                "risk_object_field": ro.field,
                                "risk_object_type": ro.type,
                                "risk_score": ro.score,
                            }
                        )
                if risk.threat_objects:
                    for to in risk.threat_objects:
                        risk_config_list.append(
                            {
                                "threat_object_field": to.field,
                                "threat_object_type": to.type,
                            }
                        )
                if risk_config_list:
                    config["action.risk.param._risk"] = json.dumps(risk_config_list)
                if risk.message:
                    config["action.risk.param._risk_message"] = risk.message

            # Email
            if acts.email:
                email = acts.email
                if email.to:
                    config["action.email.to"] = email.to
                if email.cc:
                    config["action.email.cc"] = email.cc
                if email.bcc:
                    config["action.email.bcc"] = email.bcc
                if email.priority:
                    config["action.email.priority"] = email.priority
                if email.subject:
                    config["action.email.subject"] = email.subject
                if email.message:
                    config["action.email.message.alert"] = email.message
                if email.content_type:
                    config["action.email.content_type"] = email.content_type
                if email.send_csv is not None:
                    config["action.email.sendcsv"] = (
                        1 if email.send_csv else 0
                    )
                if email.send_pdf is not None:
                    config["action.email.sendpdf"] = (
                        1 if email.send_pdf else 0
                    )
                if email.inline_results is not None:
                    config["action.email.inline"] = (
                        1 if email.inline_results else 0
                    )
                if email.include:
                    inc = email.include
                    if inc.results_link is not None:
                        config["action.email.include.results_link"] = (
                            1 if inc.results_link else 0
                        )
                    if inc.search_string is not None:
                        config["action.email.include.search"] = (
                            1 if inc.search_string else 0
                        )
                    if inc.trigger_condition is not None:
                        config["action.email.include.trigger"] = (
                            1 if inc.trigger_condition else 0
                        )
                    if inc.trigger_time is not None:
                        config["action.email.include.trigger_time"] = (
                            1 if inc.trigger_time else 0
                        )

        # ── Responders ────────────────────────────────────────────────
        responders = (
            getattr(data.response, "responders", None) or ""
        )
        config["alert.managedBy"] = responders

        # ── Advanced passthrough config ───────────────────────────────
        if splunk_config.advanced:
            for k, v in splunk_config.advanced.items():
                config[k] = str(v)

        # ── Human-readable description ────────────────────────────────
        config["description"] = data.description or ""

        return config

    # ─── Single MDR deployment ────────────────────────────────────────

    def deploy_mdr(
        self,
        data: TideModels.MDR,
        service,
        tenant_config: TideConfigs.Systems.Splunk.Tenant,
    ):
        """Deploy a single typed MDR to Splunk, handling create/update/delete.

        The MDR received here has already been processed by the central
        TideDeployment.modifiers_resolver() — all modifier transformations
        (defaults, status-based overrides, tenant scoping) are already applied
        to the typed MDR object (scheduling, trigger, actions, etc.).

        However, modifiers may also carry flat Splunk savedsearches.conf attributes
        (e.g. ``dispatch.latest_time``, ``alert.severity``) that don't map to the
        typed dataclass. These are resolved here using correct precedence:
        - Default modifiers (``default=true``) fill gaps only
        - Status/tenant modifiers override unconditionally
        """

        splunk_config = data.configurations.splunk
        if not splunk_config:
            log("SKIP", "Skipping MDR without Splunk config", data.name)
            return None

        tenant_setup = tenant_config.setup
        mdr_config = self.config_mdr(data, tenant_setup)

        name = data.name.strip()
        status = splunk_config.status
        query = create_query_v4(data)

        enable_correlation = self._should_enable_correlation_search(
            tenant_setup, splunk_config
        )
        if enable_correlation:
            name += " - Rule"

        # ── Modifier-driven flat attributes ───────────────────────────
        # The central modifiers_resolver handles typed fields (scheduling,
        # trigger, etc.) at the MDR object level. But modifiers also carry
        # flat Splunk attributes (dispatch.latest_time, alert.severity, etc.)
        # that only make sense at the savedsearches.conf level.
        # Resolve them here with correct precedence.
        status_allowed_actions = self.SPLUNK_ACTIONS
        default_attributes: dict = {}
        override_attributes: dict = {}

        if self.STATUS_MODIFIERS:
            for mod in self.STATUS_MODIFIERS:
                match = False
                is_default = mod.conditions.default is True

                if is_default:
                    match = True
                if mod.conditions.status and status in mod.conditions.status:
                    match = True
                if mod.conditions.tenants:
                    if tenant_config.name in mod.conditions.tenants:
                        match = True
                    else:
                        match = False

                if match:
                    log("INFO", f"Modifier matched: {mod.name or 'unnamed'}",
                        str(mod.conditions))
                    if is_default:
                        default_attributes.update(mod.modifications)
                    else:
                        override_attributes.update(mod.modifications)

        # Handle allowed_actions directive (deployment control, not a Splunk attr)
        for attrs in (default_attributes, override_attributes):
            if "allowed_actions" in attrs:
                allowed_actions_config = attrs.pop("allowed_actions")
                if allowed_actions_config in [False, None]:
                    log("INFO", "Actions suppressed by modifier directive", status)
                    status_allowed_actions = []
                elif isinstance(allowed_actions_config, list):
                    status_allowed_actions = allowed_actions_config

        # Apply defaults (fill gaps only — never overwrite rule-specific values)
        for k, v in default_attributes.items():
            if k not in mdr_config:
                mdr_config[k] = v

        # Apply overrides (always take precedence)
        if override_attributes:
            log("INFO", f"Applying override modifiers for {status}",
                str(override_attributes))
            mdr_config.update(override_attributes)

        # ── Actions enablement ────────────────────────────────────────
        # Platform-specific logic: determine which Splunk actions to enable
        # based on what action parameters are present in the config.
        actions_config: dict = {}

        if self.SPLUNK_ACTIONS:
            triggered_actions = []
            for action in self.SPLUNK_ACTIONS:
                for param in mdr_config:
                    if "action." + action in param:
                        if action in status_allowed_actions:
                            triggered_actions.append(action)
                            actions_config["action." + action] = 1
                            break

            if not triggered_actions:
                triggered_actions = [
                    action
                    for action in self.SPLUNK_DEFAULT_ACTIONS
                    if action in status_allowed_actions
                ]

            if triggered_actions:
                actions_config["actions"] = ", ".join(triggered_actions)

                if "notable" in triggered_actions:
                    if "action.notable.param.rule_title" not in mdr_config:
                        actions_config["action.notable.param.rule_title"] = name
                        actions_config["action.notable.param.rule_description"] = (
                            data.description or ""
                        )
                        severity = getattr(data.response, "alert_severity", "Low")
                        actions_config["action.notable.param.severity"] = severity.lower()

                    if security_domain := mdr_config.get("action.notable.param.security_domain"):
                        mdr_config["action.notable.param.security_domain"] = security_domain.lower()

                if "risk" in triggered_actions:
                    actions_config["action.risk.param._risk_score"] = 0
            else:
                actions_config["actions"] = ""

        # ── Assemble final deploy config ──────────────────────────────
        deploy_config: dict = {}
        deploy_config.update(mdr_config)
        deploy_config.update(actions_config)
        deploy_config["search"] = query

        log("INFO", "The following configuration was compiled")
        print(json.dumps(deploy_config, indent=1, sort_keys=True, default=str))

        # ── Two-stage attribute deployment ────────────────────────────
        # In Splunk, some configurations are coupled with others. The update()
        # method of saved_searches objects does not resolve this, and depending
        # on the order of the attributes in the kwargs passed may hit blocks.
        second_stage_attributes = [
            "alert.suppress",
            "is_scheduled",
            "actions",
            "search",
        ]
        second_stage: dict = {}
        for attribute in second_stage_attributes:
            if attribute in deploy_config:
                second_stage[attribute] = deploy_config.pop(attribute)

        # ── Create or locate saved search ─────────────────────────────
        try:
            selected_search = service.saved_searches[name]
            log("INFO", "Found existing saved search", name)
        except Exception:
            if check_status(status) is StatusStrategy.DELETION:
                log("SKIP", "Saved search was already non existent, no action required", name)
                return None
            else:
                log("ONGOING", "Will create a new saved search", name)
                selected_search = service.saved_searches.create(name, search=query)

        # ── Handle REMOVED rules ──────────────────────────────────────
        if check_status(status) is StatusStrategy.DELETION:
            service.saved_searches.delete(name)
            log("WARNING", f"Deleted splunk alert", name)
            return None

        # ── Write to Splunk ───────────────────────────────────────────
        if self.DEBUG_STEP:
            for k, v in deploy_config.items():
                log("ONGOING", f"Updating value {k} with {v}")
                selected_search.update(**{k: v})
            if second_stage:
                for k, v in second_stage.items():
                    log("ONGOING", f"Updating value {k} with {v}")
                    selected_search.update(**{k: v})
        else:
            selected_search.update(**deploy_config)
            if second_stage:
                selected_search.update(**second_stage)

        log("SUCCESS", "Deployed on Splunk", name)
        return True

    # ─── Interface: DeployMDR.deploy() ────────────────────────────────

    def deploy(
        self,
        mdr_deployment: Sequence[TideModels.MDR] | list[str],
        deployment_plan: DeploymentStrategy,
    ):
        """Deploy Splunk MDRs through the central TideDeployment framework.

        This is the DeployMDR interface implementation. It delegates modifier
        resolution, tenant routing, and deployment strategy to the central
        TideDeployment framework, then handles platform-specific Splunk API
        interactions for each resolved MDR.
        """

        self.configure_proxy()

        loaded_mdr = []
        for mdr in mdr_deployment:
            if type(mdr) is str:
                loaded_mdr.append(DataTide.Models.MDR[mdr])
            elif type(mdr) is TideModels.MDR:
                loaded_mdr.append(mdr)
        mdr_deployment = loaded_mdr

        if not mdr_deployment:
            log("SKIP", "No MDRs to deploy for Splunk")
            return

        deployment_obj = TideDeployment(
            deployment=mdr_deployment,
            system=DetectionSystems.SPLUNK,
            strategy=deployment_plan,
        )

        for tenant_deployment in deployment_obj.rule_deployment:  # type:ignore
            tenant_deployment: TenantDeployment.Splunk  # type:ignore

            tenant = tenant_deployment.tenant
            log("ONGOING", "Currently targeting tenant", tenant.name)

            service = connect_splunk(
                host=tenant.setup.url,
                port=tenant.setup.port,
                token=tenant.setup.token,
                app=tenant.setup.app,
                ssl_enabled=tenant.setup.ssl,
            )

            for mdr in tenant_deployment.rules:
                log("ONGOING", "Processing rule", mdr.name, mdr.metadata.uuid)
                self.deploy_mdr(
                    data=mdr,
                    service=service,
                    tenant_config=tenant,
                )


def declare():
    return SplunkDeploy()


if __name__ == "__main__" and DebugEnvironment.ENABLED:
    SplunkDeploy().deploy(
        DebugEnvironment.MDR_DEPLOYMENT_TEST_UUIDS, DeploymentStrategy.DEBUG)

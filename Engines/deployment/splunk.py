import os
import git
import sys
import json
from typing import Literal, Sequence
from pprint import pprint

import pandas as pd

sys.path.append(str(git.Repo(".", search_parent_directories=True).working_dir))

from Engines.modules.splunk import (
    SplunkEngineInit,
    connect_splunk,
    cron_to_timeframe,
    create_query,
    create_query_v4,
    splunk_timerange,
)
from Engines.modules.framework import (
    get_value_metaschema,
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

    def config_mdr(self, mdr):
        """
        Compiled the configuration that will be written to the saved search object.
        """
        # TODO: DEPRECATED [splunk-mdrv4] — Replace with config_mdr_v4() for splunk::3.0 MDRs

        config = dict()

        # Before processing MDR data, adding config configuration
        uuid = mdr.get("uuid") or mdr["metadata"]["uuid"]
        name = mdr["name"].strip()
        description = mdr["description"]
        mdr_splunk = mdr["configurations"]["splunk"]
        advanced_config = mdr_splunk.pop(
            "advanced", None
        )  # Remove advanced config and keep it separate
        
        # Normalize all types to string by safety
        if advanced_config:
            advanced_config = {k: str(v) for k,v in advanced_config.items()}
        
        # Exception for risk, as is a particular data structure in Splunk
        risk = mdr_splunk.get("risk")
        if risk:
            risk = mdr_splunk.pop("risk")

        mdr_splunk = pd.json_normalize(mdr_splunk, sep="|").to_dict(orient="records")[0]
        for key in mdr_splunk.copy():  # Avoids dict mutation errors
            new_key = str(key).split("|")[
                -1
            ]  # type:ignore Keep only the string after the last separator
            mdr_splunk[new_key] = mdr_splunk.pop(key)

        for key in mdr_splunk:
            param_name = get_value_metaschema(
                key, self.SPLUNK_SUBSCHEMA, "tide.mdr.parameter"
            )
            data = mdr_splunk[key]

            if key == "lookback":
                data = splunk_timerange(
                    data, skewing=self.SKEWING_VALUE, offset=self.OFFSET
                )

            if key == "duration":
                config["alert.suppress"] = "true"

            if key == "frequency":
                # If there is no cron expression, we assign the parameter of cron on it which will deploy
                if "cron" not in mdr_splunk:
                    custom_time = mdr_splunk.get(
                        "custom_time"
                    )  # Check if there is a custom time the rule should trigger at
                    if custom_time:
                        data = cron_to_timeframe(
                            data, mode="custom", custom_time=custom_time
                        )
                    else:
                        data = cron_to_timeframe(data, mode=self.TIMERANGE_MODE)
                    param_name = get_value_metaschema(
                        "cron", self.SPLUNK_SUBSCHEMA, "tide.mdr.parameter"
                    )

            # Splunk mostly expects comma separated list when multiple values are present
            if type(data) == list:
                data = ", ".join(data)

            if type(data) == str:
                data = data.strip()

            if param_name:
                config[param_name] = data

        # Disabled Check
        status = mdr_splunk["status"]
        if check_status(status) is StatusStrategy.DISABLEMENT:
            config["disabled"] = "true"
            log("INFO", "Configuring saved search as disabled")

        # Alert Severity Configuration
        config["alert.severity"] = self.ALERT_SEVERITY_MAPPING[
            mdr["response"]["alert_severity"]
        ]

        # Risk action has a specific implementation in Splunk where it fully relies on a
        # single flattened JSON string to represent the entire risk configuration. This is
        # unique in Splunk and is most likely explained by the fact that risk is a list of dictionaries,
        # which can't be represented in the flat key:value structure of savedsearches.conf
        if risk:
            risk_config = []
            risk_param = get_value_metaschema(
                "risk", self.SPLUNK_SUBSCHEMA, "tide.mdr.parameter"
            )
            risk_objects_config = []
            threat_objects_config = []
            risk_message = risk.get("message")
            if ro := risk.get("risk_objects"):
                for risk_object in ro:
                    risk_object_paramed = {}
                    for key in risk_object:
                        risk_object_paramed[
                            get_value_metaschema(
                                key,
                                self.SPLUNK_SUBSCHEMA,
                                "tide.mdr.parameter",
                                scope="risk_objects",
                            )
                        ] = risk_object[key]
                    risk_objects_config.append(risk_object_paramed)

            if to := risk.get("threat_objects"):
                for threat_object in to:
                    threat_object_paramed = {}
                    for key in threat_object:
                        threat_object_paramed[
                            get_value_metaschema(
                                key,
                                self.SPLUNK_SUBSCHEMA,
                                "tide.mdr.parameter",
                                scope="threat_objects",
                            )
                        ] = threat_object[key]
                    threat_objects_config.append(threat_object_paramed)

            risk_config = risk_objects_config + threat_objects_config
            if risk_config:
                config[risk_param] = json.dumps(risk_config)
            if risk_message:
                config[
                    get_value_metaschema(
                        "message",
                        self.SPLUNK_SUBSCHEMA,
                        "tide.mdr.parameter",
                        scope="risk",
                    )
                ] = risk_message

        # If there are advanced configurations, add it to the otherall config
        if advanced_config:
            for adv in advanced_config:
                config[adv] = advanced_config[adv]

        # Add ManagedBy and set to responders
        responders = mdr.get("response", {}).get("responders") or ""
        config["alert.managedBy"] = responders

        # Add correlation search setup
        if self.CORRELATION_SEARCHES:
            config["action.correlationsearch.enabled"] = "true"
            # For compatibility with Splunk Enterprise Security post-processing on
            # correlation searches, append " - Rule" to the correlation search label
            config["action.correlationsearch.label"] = name + " - Rule"
            techniques = techniques_resolver(uuid)
            if techniques:
                config["action.correlationsearch.annotations.mitre_attack"] = ", ".join(
                    techniques
                )

        # Human readable description
        config["description"] = description
        return config

    def deploy_mdr(self, mdr, service):
        """
        Deployment routine, connecting to the platform and combining base and custom configurations
        """
        # TODO: DEPRECATED [splunk-mdrv4] — Replace with deploy_mdr_v4() for splunk::3.0 MDRs

        # Generate saved search configuration
        mdr_config = self.config_mdr(mdr)

        # Fetch name for the saved search
        name: str = mdr["name"].strip()
        if self.CORRELATION_SEARCHES:
            # For compatibility with Splunk Enterprise Security post-processing on
            # correlation searches, append " - Rule" to the saved search name
            name += " - Rule"

        mdr_splunk: dict = mdr["configurations"]["splunk"]
        status: str = mdr_splunk["status"]
        query = create_query(mdr)

        # By default, status allows all the actions supported by the global config
        status_allowed_actions = self.SPLUNK_ACTIONS

        # Add status specific parameters
        status_modifiers = self.STATUS_MODIFIERS.get(status) or {}

        if status_modifiers:
            if "allowed_actions" in status_modifiers:
                allowed_actions_config = status_modifiers.pop("allowed_actions")
                # If explicitely set to False, we blank the actions allowed
                if allowed_actions_config in [False, None]:
                    log(
                        "INFO",
                        "This MDR will not have any action enabled in Splunk, as actions_enabled is set to False",
                        status,
                    )
                    status_allowed_actions = []
                else:
                    log(
                        "INFO",
                        "The enabled actions for this MDR will be constrained by the status modifier actions_enabled",
                        allowed_actions_config,
                    )
                    status_allowed_actions = allowed_actions_config

            # We pop out allowed_actions, remainder are attributes
            if status_modifiers:
                log(
                    "INFO",
                    f"Applying status modifiers for {status}",
                    str(status_modifiers),
                )
                mdr_config.update(status_modifiers)

        actions_config = {}

        # Add allowed splunk actions once the entire MDR is configured
        if self.SPLUNK_ACTIONS:
            # We enable the action only when a configuration has been set related to this action
            # For example, we may allow action.email, but will only configure it as enabled
            # if some parameter in the config related to it were configured
            triggered_actions = []
            for action in self.SPLUNK_ACTIONS:
                for param in mdr_config:
                    if "action." + action in param:
                        if action in status_allowed_actions:
                            triggered_actions.append(action)
                            actions_config["action." + action] = (
                                1  # Turning on the action
                            )
                            break

            if not triggered_actions:
                # Allowing default actions if they are not denied at status config level
                triggered_actions = [
                    action
                    for action in self.SPLUNK_DEFAULT_ACTIONS
                    if action in status_allowed_actions
                ]

            if triggered_actions:
                actions_config["actions"] = ", ".join(triggered_actions)

                # Actions modifiers which automate certain attributes bound to the action being allocated
                if "notable" in triggered_actions:
                    # Assign default notable title if not specified in mdr config
                    if "action.notable.param.rule_title" not in mdr_config:
                        actions_config["action.notable.param.rule_title"] = name
                        actions_config["action.notable.param.rule_description"] = (
                            mdr.get("description") or ""
                        )
                        actions_config["action.notable.param.severity"] = mdr[
                            "response"
                        ]["alert_severity"].lower()
                        
                    # Ensuring security domain is lowercased
                    if  security_domain:=mdr_config.get("action.notable.param.security_domain"):
                        mdr_config["action.notable.param.security_domain"] = security_domain.lower()
                if "risk" in triggered_actions:
                    # Explicitely set _risk_score to 0 since it is set to 1 by the platform
                    # as a way to show a default GUI, but interferes with automation.
                    # All risk configuration are carried by action.notable.param._risk in a JSON bundle
                    actions_config["action.risk.param._risk_score"] = 0

            else:
                actions_config["actions"] = ""

        deploy_config = self.DEFAULT_CONFIG.copy()
        deploy_config.update(mdr_config)
        deploy_config.update(actions_config)
        deploy_config["search"] = query

        log("INFO", "The following configuration was compiled")
        print(json.dumps(deploy_config, indent=1, sort_keys=True))

        # In Splunk, some configurations are coupled with others. The update()
        # method of saved_searches objects does not resolve this, and depending on the
        # order of the attrributes in the kwargs passed may hit blocks.
        #
        # This workaround lifts some of those identified blockers and will roll them out
        # after their dependencies, which are deployed first.

        second_stage_attributes = [
            "alert.suppress",  # needs alert.suppress.period to be set first
            "is_scheduled",  # needs alert_comparator to be set first
            "actions",  # requires other action namespace item to be set first
            "search",  # empirical testing show that the search don't update properly if not last
        ]
        second_stage = dict()

        for attribute in second_stage_attributes:
            if attribute in deploy_config:
                second_stage[attribute] = deploy_config.pop(attribute)

        # Check if saved search already exists or create a new one
        try:
            selected_search = service.saved_searches[name]
            log("INFO", "Found existing saved search", name)
        except:
            # Special case for removed rules, do not bother with recreating
            if check_status(status) is StatusStrategy.DELETION:
                log(
                    "SKIP",
                    f"Saved search was already non existent, no action required",
                    name
                )
                return None

            # For all other rules, create a new saved search
            else:
                log("ONGOING", "Will create a new saved search", name)
                selected_search = service.saved_searches.create(name, search=query)

        # Steps to handle REMOVED rules
        if check_status(status) is StatusStrategy.DELETION:
            service.saved_searches.delete(name)
            log("WARNING", f"Deleted splunk alert", name)
            return None

        # Debugging output; sets attribute one by one
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

            # Rolling out attributes with dependencies that will block the deployment if out of order.
            if second_stage:
                selected_search.update(**second_stage)
        log("SUCCESS", "Deployed on Splunk", name)

        return True

    # ─── MDRv4 typed methods ───────────────────────────────────────────

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

    def config_mdr_v4(
        self,
        data: TideModels.MDR,
        tenant_setup: TideConfigs.Systems.Splunk.Tenant.Setup,
    ) -> dict:
        """Build the savedsearches.conf attribute dict from a typed MDR object.

        This replaces the pandas json_normalize approach used in v3 with direct
        typed attribute access.
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

    def deploy_mdr_v4(
        self,
        data: TideModels.MDR,
        service,
        tenant_config: TideConfigs.Systems.Splunk.Tenant,
    ):
        """Deploy a single typed MDR to Splunk, handling create/update/delete."""

        splunk_config = data.configurations.splunk
        if not splunk_config:
            log("SKIP", "Skipping MDR without Splunk config", data.name)
            return None

        tenant_setup = tenant_config.setup
        mdr_config = self.config_mdr_v4(data, tenant_setup)

        name = data.name.strip()
        status = splunk_config.status
        query = create_query_v4(data)

        enable_correlation = self._should_enable_correlation_search(
            tenant_setup, splunk_config
        )
        if enable_correlation:
            name += " - Rule"

        # Status modifiers
        status_allowed_actions = self.SPLUNK_ACTIONS
        status_modifiers = (self.STATUS_MODIFIERS or {}).get(status) or {}

        if status_modifiers:
            status_modifiers = dict(status_modifiers)
            if "allowed_actions" in status_modifiers:
                allowed_actions_config = status_modifiers.pop("allowed_actions")
                if allowed_actions_config in [False, None]:
                    log("INFO", "Actions will be suppressed for this MDR", status)
                    status_allowed_actions = []
                else:
                    status_allowed_actions = allowed_actions_config

            if status_modifiers:
                log("INFO", f"Applying status modifiers for {status}", str(status_modifiers))
                mdr_config.update(status_modifiers)

        # Actions enablement
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

        deploy_config = (self.DEFAULT_CONFIG or {}).copy()
        deploy_config.update(mdr_config)
        deploy_config.update(actions_config)
        deploy_config["search"] = query

        log("INFO", "The following configuration was compiled")
        print(json.dumps(deploy_config, indent=1, sort_keys=True, default=str))

        # Two-stage attribute deployment
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

        # Check if saved search exists or create
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

        # Handle REMOVED rules
        if check_status(status) is StatusStrategy.DELETION:
            service.saved_searches.delete(name)
            log("WARNING", f"Deleted splunk alert", name)
            return None

        # Deploy
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

    # ─── Legacy MDRv3 deploy ──────────────────────────────────────────
    # TODO: DEPRECATED [splunk-mdrv4] — Remove after full migration to splunk::3.0

    def deploy_legacy(self, deployment: list[str]):
        """MDRv3 deployment path for pre-3.0 Splunk MDRs using dict-based access."""

        if not deployment:
            raise Exception("DEPLOYMENT NOT FOUND")

        self.configure_proxy()

        service = connect_splunk(
            host=self.SPLUNK_URL,
            port=self.SPLUNK_PORT,
            token=self.SPLUNK_TOKEN,
            app=self.SPLUNK_APP,
            ssl_enabled=self.SSL_ENABLED
        )

        # Start deployment routine
        for mdr in deployment:
            mdr_data = DataTide.Models.mdr[mdr]

            # Check if modified MDR contains a platform entry (by safety, but should not happen since
            # the orchestrator will filter for the platform)
            if self.DEPLOYER_IDENTIFIER in mdr_data["configurations"].keys():
                # Connection routine, if not connected yet.
                log("ONGOING", f"Currently deploying MDR {mdr_data['name']}...")
                self.deploy_mdr(mdr_data, service)
            else:
                log(
                    "SKIP",
                    f"Skipping {mdr_data.get('name')} as does not contain a Splunk rule",
                )

    # ─── Unified deploy supporting both v3 and v4 ────────────────────

    def deploy(
        self,
        mdr_deployment: Sequence[TideModels.MDR] | list[str] | None = None,
        deployment_plan: DeploymentStrategy | None = None,
        deployment: list[str] | None = None,
    ):
        """Deploy Splunk MDRs — supports both MDRv3 (list of UUIDs) and MDRv4 (typed) signatures.

        The orchestrator calls either:
          - deploy(deployment=["uuid1", ...])  (v3 path)
          - deploy(mdr_deployment=[...], deployment_plan=PRODUCTION)  (v4 path)
        """

        # ── MDRv3 fallback: called with deployment= keyword ──────────
        if deployment is not None and mdr_deployment is None:
            log("INFO", "Using legacy MDRv3 deployment path for Splunk")
            self.deploy_legacy(deployment)
            return

        if mdr_deployment is None:
            raise Exception("No deployment target provided")

        # ── MDRv4 path ────────────────────────────────────────────────
        self.configure_proxy()

        loaded_mdr = []
        for mdr in mdr_deployment:
            if type(mdr) is str:
                loaded_mdr.append(DataTide.Models.MDR[mdr])
            elif type(mdr) is TideModels.MDR:
                loaded_mdr.append(mdr)
        mdr_deployment = loaded_mdr

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
                ssl_enabled=self.SSL_ENABLED,
            )

            for mdr in tenant_deployment.rules:
                log("ONGOING", "Processing rule", mdr.name, mdr.metadata.uuid)
                self.deploy_mdr_v4(
                    data=mdr,
                    service=service,
                    tenant_config=tenant,
                )

def declare():
    return SplunkDeploy()

if __name__ == "__main__" and DebugEnvironment.ENABLED:
    SplunkDeploy().deploy(DebugEnvironment.MDR_DEPLOYMENT_TEST_UUIDS)

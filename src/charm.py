#!/usr/bin/env python3
# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

"""Charmed k8s Operator for Apache ZooKeeper."""

import logging
import time

from charms.grafana_k8s.v0.grafana_dashboard import GrafanaDashboardProvider
from charms.loki_k8s.v0.loki_push_api import LogProxyConsumer
from charms.prometheus_k8s.v0.prometheus_scrape import MetricsEndpointProvider
from charms.rolling_ops.v0.rollingops import RollingOpsManager
from ops.charm import (
    CharmBase,
    InstallEvent,
    LeaderElectedEvent,
    RelationDepartedEvent,
)
from ops.framework import EventBase
from ops.main import main
from ops.model import ActiveStatus, MaintenanceStatus, ModelError, WaitingStatus

from core.cluster import ClusterState
from events.password_actions import PasswordActionEvents
from events.provider import ProviderEvents
from events.tls import TLSEvents
from literals import (
    CHARM_KEY,
    CHARM_USERS,
    CONTAINER,
    JMX_PORT,
    LOGS_RULES_DIR,
    METRICS_PROVIDER_PORT,
    METRICS_RULES_DIR,
    SUBSTRATE,
)
from managers.config import ConfigManager
from managers.quorum import QuorumManager
from managers.tls import TLSManager
from workload import ZKWorkload

logger = logging.getLogger(__name__)


class ZooKeeperCharm(CharmBase):
    """Charmed Operator for ZooKeeper K8s."""

    def __init__(self, *args):
        super().__init__(*args)
        self.name = CHARM_KEY
        self.state = ClusterState(self, substrate=SUBSTRATE)
        self.workload = ZKWorkload(container=self.unit.get_container(CONTAINER))

        # --- CHARM EVENT HANDLERS ---

        self.password_action_events = PasswordActionEvents(self)
        self.tls_events = TLSEvents(self)
        self.provider_events = ProviderEvents(self)

        # --- MANAGERS ---

        self.quorum_manager = QuorumManager(state=self.state)
        self.tls_manager = TLSManager(
            state=self.state, workload=self.workload, substrate=SUBSTRATE
        )
        self.config_manager = ConfigManager(
            state=self.state, workload=self.workload, substrate=SUBSTRATE, config=self.config
        )

        # --- LIB EVENT HANDLERS ---

        self.restart = RollingOpsManager(self, relation="restart", callback=self._restart)
        self.grafana_dashboards = GrafanaDashboardProvider(self)
        self.metrics_endpoint = MetricsEndpointProvider(
            self,
            refresh_event=self.on.start,
            alert_rules_path=METRICS_RULES_DIR,
            jobs=[
                {"static_configs": [{"targets": [f"*:{JMX_PORT}", f"*:{METRICS_PROVIDER_PORT}"]}]}
            ],
        )
        self.loki_push = LogProxyConsumer(
            self,
            log_files=["/var/log/zookeeper/zookeeper.log"],  # FIXME: update when rebased on merged
            alert_rules_path=LOGS_RULES_DIR,
            relation_name="logging",
            container_name=CONTAINER,
        )
        # --- CORE EVENTS ---

        self.framework.observe(getattr(self.on, "install"), self._on_install)
        self.framework.observe(getattr(self.on, "update_status"), self.update_quorum)
        self.framework.observe(getattr(self.on, "upgrade_charm"), self._on_zookeeper_pebble_ready)
        self.framework.observe(getattr(self.on, "start"), self._on_zookeeper_pebble_ready)
        self.framework.observe(
            getattr(self.on, "zookeeper_pebble_ready"), self._on_zookeeper_pebble_ready
        )
        self.framework.observe(
            getattr(self.on, "leader_elected"), self._on_cluster_relation_changed
        )
        self.framework.observe(
            getattr(self.on, "config_changed"), self._on_cluster_relation_changed
        )

        self.framework.observe(
            getattr(self.on, "cluster_relation_changed"), self._on_cluster_relation_changed
        )
        self.framework.observe(
            getattr(self.on, "cluster_relation_joined"), self._on_cluster_relation_changed
        )
        self.framework.observe(
            getattr(self.on, "cluster_relation_departed"), self._on_cluster_relation_changed
        )

    # --- CORE EVENT HANDLERS ---

    def _on_install(self, event: InstallEvent) -> None:
        """Handler for the `on_install` event."""
        # don't complete install until passwords set
        if not self.state.peer_relation:
            self.unit.status = WaitingStatus("waiting for peer relation")
            event.defer()
            return

        if self.unit.is_leader() and not self.state.cluster.internal_user_credentials:
            for user in CHARM_USERS:
                self.state.cluster.update({f"{user}-password": self.workload.generate_password()})

        # give the leader a default quorum during cluster initialisation
        if self.unit.is_leader():
            self.state.cluster.update({"quorum": "default - non-ssl"})

    def _on_cluster_relation_changed(self, event: EventBase) -> None:
        """Generic handler for all 'something changed, update' events across all relations."""
        if not self.workload.alive():
            event.defer()
            return

        # not all methods called
        if not self.state.peer_relation:
            return

        # attempt startup of server
        if not self.state.unit_server.started:
            self.init_server()

        # even if leader has not started, attempt update quorum
        self.update_quorum(event=event)

        # don't delay scale-down leader ops by restarting dying unit
        if getattr(event, "departing_unit", None) == self.unit:
            return

        # check whether restart is needed for all `*_changed` events
        # only restart where necessary to avoid slowdowns
        # config_changed call here implicitly updates jaas + zoo.cfg
        if (
            self.config_manager.config_changed() or self.state.cluster.switching_encryption
        ) and self.state.unit_server.started:
            self.on[f"{self.restart.name}"].acquire_lock.emit()

        # ensures events aren't lost during an upgrade on single units
        if self.state.cluster.switching_encryption and len(self.state.servers) == 1:
            event.defer()

    def _on_zookeeper_pebble_ready(self, event: EventBase) -> None:
        """Handler for the `upgrade-charm`, `zookeeper-pebble-ready` and `start` events.

        Handles case where workload has shut down due to failing `ruok` 4lw command and
        needs to be restarted.
        """
        # FIXME: Will need updating when adding in-place upgrade support
        # ensure pebble-ready only fires after normal peer-relation-driven server init
        if not self.workload.alive or not self.state.unit_server.started:
            event.defer()
            return

        try:
            if self.workload.healthy:
                return  # nothing to do, service is up and running, don't replan
        except ModelError:
            logger.info(f"{CONTAINER} workload service not running, re-initialising...")

        # re-initialise + replan pebble layer if no service, or service not running
        self.init_server()

    def _restart(self, event: EventBase) -> None:
        """Handler for emitted restart events."""
        # this can cause issues if ran before `init_server()`
        if not self.state.stable:
            event.defer()
            return

        logger.info(f"{self.unit.name} restarting...")
        self.workload.restart()

        # gives time for server to rejoin quorum, as command exits too fast
        # without, other units might restart before this unit rejoins, losing quorum
        time.sleep(5)

        self.unit.status = ActiveStatus()

        self.state.unit_server.update(
            {
                # flag to declare unit running `portUnification` during ssl<->no-ssl upgrade
                "unified": "true" if self.state.cluster.switching_encryption else "",
                # flag to declare unit restarted with new quorum encryption
                "quorum": self.state.cluster.quorum,
                # indicate that unit has completed restart on password rotation
                "password-rotated": "true" if self.state.cluster.rotate_passwords else "",
            }
        )

        self.update_client_data()

    # --- CONVENIENCE METHODS ---

    def init_server(self):
        """Calls startup functions for server start.

        Sets myid, server_jvmflgas env_var, initial servers in dynamic properties,
            default properties and jaas_config
        """
        # don't run if leader has not yet created passwords
        if not self.state.cluster.internal_user_credentials:
            self.unit.status = MaintenanceStatus("waiting for passwords to be created")
            return

        # don't run (and restart) if some units are still joining
        # instead, wait for relation-changed from it's setting of 'started'
        if not self.state.all_units_related:
            return

        # start units in order
        if (
            self.state.next_server
            and self.state.next_server.component.name != self.state.unit_server.component.name
        ):
            self.unit.status = MaintenanceStatus("waiting for unit turn to start")
            return

        self.unit.status = MaintenanceStatus("starting ZooKeeper server")
        logger.info(f"{self.unit.name} initializing...")

        # setting default properties
        self.config_manager.set_zookeeper_myid()
        self.config_manager.set_server_jvmflags()

        # servers properties needs to be written to dynamic config
        self.config_manager.set_zookeeper_dynamic_properties(servers=self.state.startup_servers)

        logger.debug("setting properties and jaas")
        self.config_manager.set_zookeeper_properties()
        self.config_manager.set_jaas_config()

        logger.debug("starting ZooKeeper service")
        self.workload.start(layer=self.config_manager.layer)
        self.unit.status = ActiveStatus()

        # unit flags itself as 'started' so it can be retrieved by the leader
        logger.info(f"{self.unit.name} started")

        # added here in case a `restart` was missed
        self.state.unit_server.update(
            {
                "state": "started",
                "unified": "true" if self.state.cluster.switching_encryption else "",
                "quorum": self.state.cluster.quorum,
            }
        )

    def update_quorum(self, event: EventBase) -> None:
        """Updates the server quorum members for all currently started units in the relation.

        Also sets app-data pertaining to quorum encryption state during upgrades.
        """
        if not self.unit.is_leader() or getattr(event, "departing_unit", None) == self.unit:
            return

        # set first unit to "added" asap to get the units starting sooner
        # sets to "added" for init quorum leader, if not already exists
        # may already exist if during the case of a failover of the first unit
        if (init_leader := self.state.init_leader) and init_leader.started:
            self.state.cluster.update({str(init_leader.unit_id): "added"})

        if (
            self.state.stale_quorum  # in the case of scale-up
            or isinstance(  # to run without delay to maintain quorum on scale down
                event,
                (RelationDepartedEvent, LeaderElectedEvent),
            )
            or self.state.healthy  # to ensure run on update-status
        ):
            updated_servers = self.quorum_manager.update_cluster()
            logger.debug(f"{updated_servers=}")

            # triggers a `cluster_relation_changed` to wake up following units
            self.state.cluster.update(updated_servers)

        # default startup without ssl relation
        logger.debug("updating quorum - checking cluster stability")
        if not self.state.stable:
            return

        # declare upgrade complete only when all peer units have started
        # triggers `cluster_relation_changed` to rolling-restart without `portUnification`
        if self.state.all_units_unified:
            logger.debug("all units unified")
            if self.state.cluster.tls:
                logger.debug("tls enabled - switching to ssl")
                self.state.cluster.update({"quorum": "ssl"})
            else:
                logger.debug("tls disabled - switching to non-ssl")
                self.state.cluster.update({"quorum": "non-ssl"})

            if self.state.all_units_quorum:
                logger.debug(
                    "all units running desired encryption - removing switching-encryption"
                )
                self.state.cluster.update({"switching-encryption": ""})
                logger.info(f"ZooKeeper cluster switching to {self.state.cluster.quorum} quorum")

        self.update_client_data()

    def update_client_data(self) -> None:
        """Writes necessary relation data to all related applications."""
        if not self.state.ready or not self.unit.is_leader():
            return

        for client in self.state.clients:
            if not client.password:
                continue  # skip as ACLs have not yet been added

            client.update(
                {
                    "uris": client.uris,
                    "endpoints": client.endpoints,
                    "tls": client.tls,
                    "username": client.username,
                    "password": client.password,
                    "chroot": client.chroot,
                }
            )


if __name__ == "__main__":
    main(ZooKeeperCharm)

#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Implementation of WorkloadBase for running on K8s."""
import logging
import secrets
import string

import httpx
from ops.model import Container
from ops.pebble import ChangeError, Layer
from tenacity import retry, retry_if_result, stop_after_attempt, wait_fixed
from typing_extensions import override

from core.workload import WorkloadBase
from literals import ADMIN_SERVER_PORT

logger = logging.getLogger(__name__)


class ZKWorkload(WorkloadBase):
    """Implementation of WorkloadBase for running on K8s."""

    def __init__(self, container: Container):
        self.container = container

    @override
    def start(self, layer: Layer) -> None:
        # ensures paths exist on mounted storage to use
        self.container.make_dir(self.paths.data_dir, make_parents=True)
        self.container.make_dir(self.paths.datalog_dir, make_parents=True)

        try:
            self.container.add_layer(self.container.name, layer, combine=True)
            self.container.replan()
        except ChangeError:
            return

    @override
    def stop(self) -> None:
        self.container.stop(self.container.name)

    @override
    def restart(self) -> None:
        self.container.restart(self.container.name)

    @override
    def read(self, path: str) -> list[str]:
        if not self.container.exists(path):
            return []

        return str(self.container.pull(path, encoding="utf-8").read()).split("\n")

    @override
    def write(self, content: str, path: str) -> None:
        self.container.push(path, content, make_dirs=True)

    @override
    def exec(self, command: list[str], working_dir: str | None = None) -> str:
        return self.container.exec(command, working_dir=working_dir).wait_output()[0]

    @property
    @override
    def alive(self) -> bool:
        if not self.container_can_connect:
            return False

        return self.container.get_service(self.container.name).is_running()

    @property
    def container_can_connect(self) -> bool:
        """Check if a connection can be made to the container."""
        return self.container.can_connect()

    @property
    @override
    @retry(
        wait=wait_fixed(1),
        stop=stop_after_attempt(5),
        retry=retry_if_result(lambda result: result is False),
        retry_error_callback=lambda _: False,
    )
    def healthy(self) -> bool:
        """Flag to check if the unit service is reachable and serving requests."""
        if not self.alive:
            return False

        try:
            response = httpx.get(f"http://127.0.0.1:{ADMIN_SERVER_PORT}/commands/ruok", timeout=10)
            response.raise_for_status()

        except httpx.HTTPError:
            return False

        if response.json().get("error", None):
            return False

        return True

    # --- ZK Specific ---

    def install(self) -> None:
        """Loads the ZooKeeper snap from LP, returning a StatusBase for the Charm to set."""
        raise NotImplementedError

    def generate_password(self) -> str:
        """Creates randomized string for use as app passwords.

        Returns:
            String of 32 randomized letter+digit characters
        """
        return "".join([secrets.choice(string.ascii_letters + string.digits) for _ in range(32)])

    @override
    def get_version(self) -> str:
        if not self.alive:
            return ""

        if not self.healthy:
            return ""

        try:
            response = httpx.get(f"http://127.0.0.1:{ADMIN_SERVER_PORT}/commands/srvr", timeout=10)
            response.raise_for_status()

        except httpx.HTTPError:
            return ""

        if not (full_version := response.json().get("version", "")):
            return full_version
        else:
            return full_version.split("-")[0]

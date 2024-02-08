#!/usr/bin/env python3
# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

import asyncio
import logging
from pathlib import Path

import pytest
import yaml
from pytest_operator.plugin import OpsTest

from . import SERIES, TLS_OPERATOR_SERIES
from .helpers import check_properties, ping_servers

logger = logging.getLogger(__name__)

METADATA = yaml.safe_load(Path("./metadata.yaml").read_text())
APP_NAME = METADATA["name"]
ZOOKEEPER_IMAGE = METADATA["resources"]["zookeeper-image"]["upstream-source"]

TLS_NAME = "self-signed-certificates"


@pytest.mark.abort_on_fail
async def test_deploy_ssl_quorum(ops_test: OpsTest):
    charm = await ops_test.build_charm(".")
    await asyncio.gather(
        ops_test.model.deploy(
            charm,
            application_name=APP_NAME,
            num_units=3,
            resources={"zookeeper-image": ZOOKEEPER_IMAGE},
            series=SERIES,
        ),
        ops_test.model.deploy(
            TLS_NAME,
            application_name=TLS_NAME,
            channel="edge",
            num_units=1,
            config={"ca-common-name": "zookeeper"},
            series=TLS_OPERATOR_SERIES,
        ),
    )
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME, TLS_NAME], status="active", timeout=1000, idle_period=30
    )
    await ops_test.model.add_relation(APP_NAME, TLS_NAME)

    async with ops_test.fast_forward():
        await ops_test.model.wait_for_idle(
            apps=[APP_NAME, TLS_NAME],
            status="active",
            timeout=1000,
            idle_period=30,
        )

    assert ping_servers(ops_test)

    for unit in ops_test.model.applications[APP_NAME].units:
        assert "sslQuorum=true" in check_properties(
            model_full_name=ops_test.model_full_name, unit=unit.name
        )


@pytest.mark.abort_on_fail
@pytest.mark.skip(reason="Remove application bad on K8s")
async def test_remove_tls_provider(ops_test: OpsTest):
    await ops_test.model.remove_application(TLS_NAME, block_until_done=True)
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME], status="active", timeout=1000, idle_period=30
    )

    assert ping_servers(ops_test)

    for unit in ops_test.model.applications[APP_NAME].units:
        assert "sslQuorum=true" not in check_properties(
            model_full_name=ops_test.model_full_name, unit=unit.name
        )


@pytest.mark.abort_on_fail
@pytest.mark.skip(reason="Remove application bad on K8s")
async def test_add_tls_provider_succeeds_after_removal(ops_test: OpsTest):
    await asyncio.gather(
        ops_test.model.deploy(
            TLS_NAME,
            application_name=TLS_NAME,
            channel="stable",
            num_units=1,
            config={"generate-self-signed-certificates": "true", "ca-common-name": "zookeeper"},
        ),
    )
    await ops_test.model.wait_for_idle(apps=[APP_NAME, TLS_NAME], status="active", timeout=1000)
    await ops_test.model.add_relation(APP_NAME, TLS_NAME)
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME, TLS_NAME], status="active", timeout=1000, idle_period=30
    )

    assert ping_servers(ops_test)

    for unit in ops_test.model.applications[APP_NAME].units:
        assert "sslQuorum=true" in check_properties(
            model_full_name=ops_test.model_full_name, unit=unit.name
        )


@pytest.mark.abort_on_fail
async def test_scale_up_tls(ops_test: OpsTest):
    await ops_test.model.applications[APP_NAME].add_units(count=1)
    await ops_test.model.block_until(lambda: len(ops_test.model.applications[APP_NAME].units) == 4)
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME], status="active", timeout=1000, idle_period=30
    )
    assert ping_servers(ops_test)


@pytest.mark.abort_on_fail
async def test_client_relate_maintains_quorum(ops_test: OpsTest):
    dummy_name = "app"
    app_charm = await ops_test.build_charm("tests/integration/app-charm")
    await ops_test.model.deploy(app_charm, application_name=dummy_name, num_units=1, series=SERIES)
    await ops_test.model.wait_for_idle(
        [APP_NAME, dummy_name], status="active", timeout=1000, idle_period=30
    )

    await ops_test.model.add_relation(APP_NAME, dummy_name)
    await ops_test.model.wait_for_idle(
        [APP_NAME, dummy_name], status="active", timeout=1000, idle_period=30
    )

    assert ping_servers(ops_test)

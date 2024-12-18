#!/usr/bin/env python3
# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Helpers for managing backups."""

import logging
import os
from datetime import datetime
from io import BytesIO, StringIO
from itertools import islice
from operator import attrgetter
from pathlib import Path

import boto3
import httpx
import yaml
from botocore import config, loaders, regions
from botocore.exceptions import ClientError
from mypy_boto3_s3.service_resource import Bucket
from rich.console import Console
from rich.table import Table

from core.cluster import ClusterState
from core.stubs import BackupMetadata, S3ConnectionInfo
from literals import ADMIN_SERVER_PORT, PATHS, S3_BACKUPS_LIMIT, S3_BACKUPS_PATH, USER
from workload import ZKWorkload

logger = logging.getLogger(__name__)


class BackupManager:
    """Manager for all things backup-related."""

    def __init__(self, state: ClusterState) -> None:
        self.state = state
        self.backups_path = S3_BACKUPS_PATH

    @property
    def bucket(self) -> Bucket:
        """S3 bucket to read from and write to."""
        s3_parameters = self.state.cluster.s3_credentials
        self.backups_path = s3_parameters["path"]
        s3 = boto3.resource(
            "s3",
            aws_access_key_id=s3_parameters["access-key"],
            aws_secret_access_key=s3_parameters["secret-key"],
            region_name=s3_parameters["region"] if s3_parameters["region"] else None,
            endpoint_url=self._construct_endpoint(s3_parameters),
            config=config.Config(retries={"mode": "standard", "max_attempts": 3}),
        )
        return s3.Bucket(s3_parameters["bucket"])

    def _construct_endpoint(self, s3_parameters: S3ConnectionInfo) -> str:
        """Construct the S3 service endpoint using the region.

        This is needed when the provided endpoint is from AWS, and it doesn't contain the region.
        """
        endpoint = s3_parameters["endpoint"]

        loader = loaders.create_loader()
        data = loader.load_data("endpoints")

        resolver = regions.EndpointResolver(data)
        endpoint_data = resolver.construct_endpoint("s3", s3_parameters["region"])

        if endpoint_data and endpoint.endswith(endpoint_data["dnsSuffix"]):
            endpoint = f'{endpoint.split("://")[0]}://{endpoint_data["hostname"]}'

        return endpoint

    def create_bucket(self, s3_parameters: S3ConnectionInfo) -> bool:
        """Create bucket if it does not exists."""
        s3 = boto3.resource(
            "s3",
            aws_access_key_id=s3_parameters["access-key"],
            aws_secret_access_key=s3_parameters["secret-key"],
            region_name=s3_parameters["region"] if s3_parameters["region"] else None,
            endpoint_url=s3_parameters["endpoint"],
        )
        bucket_name = s3_parameters["bucket"]
        bucket_exists = True

        bucket = s3.Bucket(bucket_name)  # pyright: ignore [reportAttributeAccessIssue]

        try:
            bucket.meta.client.head_bucket(Bucket=bucket_name)
        except ClientError as ex:
            if "(403)" in ex.args[0]:
                logger.error("Wrong credentials or access to bucket is forbidden")
                return False
            elif "(404)" in ex.args[0]:
                bucket_exists = False
        else:
            logger.info(f"Using existing bucket {bucket_name}")

        if not bucket_exists:
            bucket.create()
            bucket.wait_until_exists()
            logger.info(f"Created bucket {bucket_name}")

        return True

    def create_backup(self) -> BackupMetadata:
        """Create a snapshot with ZooKeeper admin server and stream it to the object storage."""
        zk_user = "super"
        zk_pwd = self.state.cluster.internal_user_credentials.get("super", "")
        date = datetime.now()
        snapshot_name = f"{date:%Y-%m-%dT%H:%M:%SZ}"

        # It is very likely that the file is fully loaded in memory, because the file-like interface is
        # not seekable, and I have a strong suspicion that boto uses this to figure out if it can
        # upload in one go or need to use a multipart request.
        # We cannot be sure because finding this information in boto code base is time consuming.
        # If this ever become an issue, we can find a workaround by using the 'content-length' header from
        # the response. Or write to a temp file as a last resort.
        with httpx.stream(
            "GET",
            f"http://127.0.0.1:{ADMIN_SERVER_PORT}/commands/snapshot?streaming=true",
            headers={"Authorization": f"digest {zk_user}:{zk_pwd}"},
        ) as response:

            response_headers = response.headers
            quorum_leader_zxid = int(response_headers["last_zxid"], base=16)
            metadata: BackupMetadata = {
                "id": snapshot_name,
                "log-sequence-number": quorum_leader_zxid,
                "path": os.path.join(self.backups_path, snapshot_name, "snapshot"),
            }

            self.bucket.put_object(
                Key=os.path.join(self.backups_path, snapshot_name, "metadata.yaml"),
                Body=yaml.dump(metadata, encoding="utf8"),
            )

            self.bucket.upload_fileobj(
                _StreamingToFileSyncAdapter(response),  # type: ignore
                os.path.join(self.backups_path, snapshot_name, "snapshot"),
            )

        return metadata

    def list_backups(self) -> list[BackupMetadata]:
        """List snapshots present in object storage."""
        backups_metadata: list[BackupMetadata] = []

        # S3 API is limited so we end up with an N+1 query problem. Thus, we limit the
        # number of backups and fetch the latest modified ones.
        remote_files = self.bucket.objects.filter(Prefix=self.backups_path)
        remote_metadata = filter(lambda rfile: rfile.key.endswith(".yaml"), remote_files)
        sorted_remote_files = sorted(
            remote_metadata, key=attrgetter("last_modified"), reverse=True
        )

        for remote_file in islice(sorted_remote_files, S3_BACKUPS_LIMIT):
            buffer = BytesIO()
            self.bucket.download_fileobj(remote_file.key, buffer)
            metadata = yaml.safe_load(buffer.getvalue())
            backups_metadata.append(metadata)

        return backups_metadata

    def format_backups_table(
        self, backup_entries: list[BackupMetadata], title: str = "Backups"
    ) -> str:
        """Format backups metadata into a readable table."""
        table = Table(title=title)

        table.add_column("Id", no_wrap=True)
        table.add_column("Log-sequence-number", justify="right")
        table.add_column("Path", overflow="fold")

        for meta in backup_entries:
            table.add_row(meta["id"], str(meta["log-sequence-number"]), meta["path"])

        out_f = StringIO()
        console = Console(file=out_f, width=79)
        console.print(table)

        return out_f.getvalue()

    def is_snapshot_in_bucket(self, backup_id: str) -> bool:
        """Check whether the requested snapshot to restore is in the object storage."""
        try:
            content = self.bucket.meta.client.head_object(
                Bucket=self.bucket.name, Key=os.path.join(self.backups_path, backup_id, "snapshot")
            )
        except ClientError as ex:
            if "(404)" in ex.args[0]:
                return False
            raise
        return bool(content.get("ResponseMetadata", None))

    def restore_snapshot(self, backup_id: str, workload: ZKWorkload) -> None:
        """Download and restore a snapshot.

        Restoring requires removing the previous files on disk. In this step, we move them to a backup folder,
        so that we can manually restore them if something goes wrong.
        """
        data_dir = Path(PATHS["DATA"]) / "data" / "version-2"
        data_log_dir = Path(PATHS["DATA"]) / "data-log" / "version-2"

        workload.exec(["bash", "-c", f"cp -rp {data_dir} {data_dir.parent / 'version-2.bak'}"])
        workload.exec(
            ["bash", "-c", f"cp -rp {data_log_dir} {data_log_dir.parent / 'version-2.bak'}"]
        )

        workload.exec(["bash", "-c", f"rm -rf {data_dir / '*'}"])
        workload.exec(["bash", "-c", f"rm -rf {data_log_dir / '*'}"])

        restored_snapshot = data_dir / "snapshot.0"
        self.bucket.Object(os.path.join(self.backups_path, backup_id, "snapshot")).download_file(
            f"{restored_snapshot}"
        )

        workload.exec(["bash", "-c", f"chown {USER}:{USER} {restored_snapshot}"])

    def cleanup_leftover_files(self, workload: ZKWorkload) -> None:
        """Cleanup the files previously stored in the data and data-log directories."""
        data_dir = Path(PATHS["DATA"]) / "data" / "version-2.bak"
        data_log_dir = Path(PATHS["DATA"]) / "data-log" / "version-2.bak"

        workload.exec(["bash", "-c", f"rm -rf {data_dir}"])
        workload.exec(["bash", "-c", f"rm -rf {data_log_dir}"])


class _StreamingToFileSyncAdapter:
    """Wrapper to make httpx.stream behave like a file-like object.

    boto needs a .read method with an optional amount-of-bytes parameter from the file-like object.
    Taken from https://github.com/encode/httpx/discussions/2296#discussioncomment-6781355
    """

    def __init__(self, response: httpx.Response):
        self.streaming_source = response.iter_bytes()
        self.buffer = b""
        self.buffer_offset = 0

    def read(self, num_bytes: int = 4096) -> bytes:
        while len(self.buffer) - self.buffer_offset < num_bytes:
            try:
                chunk = next(self.streaming_source)
                self.buffer += chunk
            except StopIteration:
                break

        if len(self.buffer) - self.buffer_offset >= num_bytes:
            data = self.buffer[self.buffer_offset : self.buffer_offset + num_bytes]
            self.buffer_offset += num_bytes
            return data
        else:
            data = self.buffer[self.buffer_offset :]
            self.buffer = b""
            self.buffer_offset = 0
            return data

"""Data source connection management service.

This service handles database connection configuration, testing, and
authentication for various data sources including GCP, SAP, and others.
Connection details are encrypted before storage.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from cryptography.fernet import Fernet
from sqlalchemy.orm import Session

# Optional driver imports - loaded lazily inside connection helpers so the
# service module can be imported even when not all drivers are installed.
try:
    from google.cloud import bigquery  # type: ignore[import]
    from google.oauth2 import service_account  # type: ignore[import]
except ImportError:
    bigquery = None  # type: ignore[assignment]
    service_account = None  # type: ignore[assignment]

try:
    import pymysql  # type: ignore[import]
except ImportError:
    pymysql = None  # type: ignore[assignment]

try:
    import psycopg2  # type: ignore[import]
except ImportError:
    psycopg2 = None  # type: ignore[assignment]

try:
    import pyodbc  # type: ignore[import]
except ImportError:
    pyodbc = None  # type: ignore[assignment]

from ..config import settings
from ..models import ConnectionStatus, DataSource, DataSourceType, User
from ..schemas import ConnectionTestResult, DataSourceCreate, DataSourceUpdate

# from exceptions import BasePrivacyException


class BasePrivacyException(Exception):
    """Base exception for privacy-related errors."""

    def __init__(self, message: str, details: dict = None):
        self.message = message
        self.details = details or {}
        super().__init__(self.message)


class DataSourceConnectionError(BasePrivacyException):
    """Raised when data source connection fails."""

    pass


class DataSourceService:
    def __init__(self, db: Session):
        self.db = db
        self.cipher_suite = Fernet(settings.encryption_key.encode())

    def _encrypt_config(self, config: dict[str, Any]) -> str:
        """Encrypt connection configuration."""
        config_json = json.dumps(config)
        encrypted = self.cipher_suite.encrypt(config_json.encode())
        return encrypted.decode()

    def _decrypt_config(self, encrypted_config: str) -> dict[str, Any]:
        """Decrypt connection configuration."""
        decrypted = self.cipher_suite.decrypt(encrypted_config.encode())
        return json.loads(decrypted.decode())

    def create_data_source(self, user: User, data: DataSourceCreate) -> DataSource:
        """Create a new data source with encrypted connection config."""
        # Encrypt sensitive connection data
        encrypted_config = self._encrypt_config(data.connection_config)

        db_data_source = DataSource(
            user_id=user.id,
            name=data.name,
            description=data.description,
            source_type=data.source_type,
            connection_config=encrypted_config,
            status=ConnectionStatus.INACTIVE,
        )

        self.db.add(db_data_source)
        self.db.commit()
        self.db.refresh(db_data_source)
        return db_data_source

    def get_data_sources(self, user: User, skip: int = 0, limit: int = 100) -> list[DataSource]:
        """Get user's data sources."""
        query = self.db.query(DataSource).filter(DataSource.user_id == user.id)
        return query.offset(skip).limit(limit).all()

    def get_data_source(self, user: User, data_source_id: int) -> DataSource | None:
        """Get a specific data source for the user."""
        return (
            self.db.query(DataSource)
            .filter(DataSource.id == data_source_id, DataSource.user_id == user.id)
            .first()
        )

    def update_data_source(
        self, user: User, data_source_id: int, data: DataSourceUpdate
    ) -> DataSource | None:  # noqa: E501
        """Update a data source."""
        data_source = self.get_data_source(user, data_source_id)
        if not data_source:
            return None

        update_data = data.model_dump(exclude_unset=True)

        # Encrypt new connection config if provided
        if "connection_config" in update_data:
            update_data["connection_config"] = self._encrypt_config(
                update_data["connection_config"]
            )  # noqa: E501

        for field, value in update_data.items():
            setattr(data_source, field, value)

        data_source.updated_at = datetime.now(timezone.utc)
        self.db.commit()
        self.db.refresh(data_source)
        return data_source

    def delete_data_source(self, user: User, data_source_id: int) -> bool:
        """Delete a data source."""
        data_source = self.get_data_source(user, data_source_id)
        if not data_source:
            return False

        self.db.delete(data_source)
        self.db.commit()
        return True

    async def test_connection(self, user: User, data_source_id: int) -> ConnectionTestResult:
        """Test connection to a data source."""
        data_source = self.get_data_source(user, data_source_id)
        if not data_source:
            raise DataSourceConnectionError("Data source not found")

        try:
            # Update status to testing
            data_source.status = ConnectionStatus.TESTING
            data_source.test_error = None
            self.db.commit()

            # Decrypt connection config
            config = self._decrypt_config(data_source.connection_config)

            # Test connection based on source type
            result = await self._test_connection_by_type(data_source.source_type, config)

            # Update data source with test results
            if result.success:
                data_source.status = ConnectionStatus.ACTIVE
                data_source.test_error = None
            else:
                data_source.status = ConnectionStatus.ERROR
                data_source.test_error = result.message

            data_source.last_tested_at = datetime.now(timezone.utc)
            self.db.commit()

            return result

        except Exception as e:
            # Update status to error
            data_source.status = ConnectionStatus.ERROR
            data_source.test_error = str(e)
            data_source.last_tested_at = datetime.now(timezone.utc)
            self.db.commit()

            return ConnectionTestResult(success=False, message=f"Connection test failed: {str(e)}")

    async def _test_connection_by_type(
        self, source_type: DataSourceType, config: dict[str, Any]
    ) -> ConnectionTestResult:  # noqa: E501
        """Test connection based on data source type."""
        try:
            if source_type == DataSourceType.GCP_BIGQUERY:
                return await self._test_bigquery_connection(config)
            elif source_type == DataSourceType.GCP_CLOUD_SQL:
                return await self._test_cloud_sql_connection(config)
            elif source_type in [DataSourceType.MYSQL, DataSourceType.POSTGRESQL]:
                return await self._test_sql_connection(source_type, config)
            elif source_type == DataSourceType.SAP_HANA:
                return await self._test_sap_hana_connection(config)
            else:
                return ConnectionTestResult(
                    success=False, message=f"Connection testing not implemented for {source_type}"
                )
        except Exception as e:
            return ConnectionTestResult(success=False, message=f"Connection test failed: {str(e)}")

    async def _test_bigquery_connection(self, config: dict[str, Any]) -> ConnectionTestResult:
        """Test BigQuery connection."""
        try:
            credentials_info = config.get("credentials")
            if isinstance(credentials_info, str):
                credentials_info = json.loads(credentials_info)

            credentials = service_account.Credentials.from_service_account_info(credentials_info)
            client = bigquery.Client(project=config["project_id"], credentials=credentials)

            # Simple test query
            query = "SELECT 1 as test_connection"
            query_job = client.query(query)
            list(query_job.result())

            return ConnectionTestResult(
                success=True,
                message="BigQuery connection successful",
                details={"project_id": config["project_id"]},
            )
        except Exception as e:
            return ConnectionTestResult(
                success=False, message=f"BigQuery connection failed: {str(e)}"
            )

    async def _test_cloud_sql_connection(self, config: dict[str, Any]) -> ConnectionTestResult:
        """Test Cloud SQL connection."""
        # Implementation would depend on the specific database type (PostgreSQL/MySQL)
        # and connection method (public IP, private IP, Cloud SQL Proxy)
        return ConnectionTestResult(
            success=False, message="Cloud SQL connection testing not fully implemented"
        )

    async def _test_sql_connection(
        self, source_type: DataSourceType, config: dict[str, Any]
    ) -> ConnectionTestResult:  # noqa: E501
        """Test SQL database connection."""
        try:
            host = config["host"]
            port = config["port"]
            database = config["database"]
            username = config["username"]
            password = config["password"]

            if source_type == DataSourceType.MYSQL:
                connection = pymysql.connect(
                    host=host,
                    port=port,
                    user=username,
                    password=password,
                    database=database,
                    connect_timeout=10,
                )
                connection.close()

            elif source_type == DataSourceType.POSTGRESQL:
                connection = psycopg2.connect(
                    host=host,
                    port=port,
                    user=username,
                    password=password,
                    database=database,
                    connect_timeout=10,
                )
                connection.close()

            return ConnectionTestResult(
                success=True,
                message=f"{source_type.value} connection successful",
                details={"host": host, "database": database},
            )

        except Exception as e:
            return ConnectionTestResult(
                success=False, message=f"{source_type.value} connection failed: {str(e)}"
            )

    async def _test_sap_hana_connection(self, config: dict[str, Any]) -> ConnectionTestResult:
        """Test SAP HANA connection."""
        try:
            # SAP HANA connection using PyODBC or hdbcli
            # This is a simplified example - in production you'd use proper SAP drivers
            connection_string = f"DRIVER={{HDBODBC}};SERVERNODE={config['host']}:{config['port']};DATABASE={config['database']};UID={config['username']};PWD={config['password']}"  # noqa: E501

            # Note: This requires SAP HANA client to be installed
            connection = pyodbc.connect(connection_string, timeout=10)
            connection.close()

            return ConnectionTestResult(
                success=True,
                message="SAP HANA connection successful",
                details={"host": config["host"], "database": config["database"]},
            )

        except Exception as e:
            return ConnectionTestResult(
                success=False, message=f"SAP HANA connection failed: {str(e)}"
            )

    def get_decrypted_config(self, user: User, data_source_id: int) -> dict[str, Any] | None:
        """Get decrypted connection config for authorized operations."""
        data_source = self.get_data_source(user, data_source_id)
        if not data_source:
            return None

        return self._decrypt_config(data_source.connection_config)

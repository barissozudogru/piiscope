"""Data source management API endpoints.

This module provides REST API endpoints for users to manage their
database connections including GCP, SAP, and other data sources.
All operations are user-scoped and connection configs are encrypted.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ..auth import get_current_user
from ..database import get_db
from ..models import User
from ..schemas import (
    ConnectionTestResult,
    DataSourceCreate,
    DataSourceOut,
    DataSourceUpdate,
    MessageResponse,
)
from ..services.data_source_service import DataSourceConnectionError, DataSourceService

router = APIRouter()


@router.post("/", response_model=DataSourceOut, status_code=status.HTTP_201_CREATED)
async def create_data_source(
    data_source: DataSourceCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Create a new data source connection."""
    service = DataSourceService(db)
    try:
        db_data_source = service.create_data_source(current_user, data_source)
        return db_data_source
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to create data source: {str(e)}",
        ) from e


@router.get("/", response_model=list[DataSourceOut])
async def list_data_sources(
    skip: int = 0,
    limit: int = 100,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List user's data sources."""
    service = DataSourceService(db)
    data_sources = service.get_data_sources(current_user, skip=skip, limit=limit)
    return data_sources


@router.get("/{data_source_id}", response_model=DataSourceOut)
async def get_data_source(
    data_source_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get a specific data source."""
    service = DataSourceService(db)
    data_source = service.get_data_source(current_user, data_source_id)
    if not data_source:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Data source not found")
    return data_source


@router.put("/{data_source_id}", response_model=DataSourceOut)
async def update_data_source(
    data_source_id: int,
    data_source_update: DataSourceUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Update a data source."""
    service = DataSourceService(db)
    try:
        updated_data_source = service.update_data_source(
            current_user, data_source_id, data_source_update
        )
        if not updated_data_source:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Data source not found"
            )
        return updated_data_source
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to update data source: {str(e)}",
        ) from e


@router.delete("/{data_source_id}", response_model=MessageResponse)
async def delete_data_source(
    data_source_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Delete a data source."""
    service = DataSourceService(db)
    success = service.delete_data_source(current_user, data_source_id)
    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Data source not found")
    return MessageResponse(message="Data source deleted successfully")


@router.post("/{data_source_id}/test", response_model=ConnectionTestResult)
async def test_data_source_connection(
    data_source_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Test connection to a data source."""
    service = DataSourceService(db)
    try:
        result = await service.test_connection(current_user, data_source_id)
        return result
    except DataSourceConnectionError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Connection test failed: {str(e)}",
        ) from e


@router.get("/{data_source_id}/tables")
async def list_tables(
    data_source_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List available tables/collections in the data source."""
    service = DataSourceService(db)
    data_source = service.get_data_source(current_user, data_source_id)
    if not data_source:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Data source not found")

    # This would need to be implemented per data source type
    # For now, return a placeholder
    return {
        "message": "Table listing not yet implemented",
        "data_source_type": data_source.source_type,
        "tables": [],
    }


@router.get("/{data_source_id}/schema")
async def get_table_schema(
    data_source_id: int,
    table_name: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get schema information for a specific table."""
    service = DataSourceService(db)
    data_source = service.get_data_source(current_user, data_source_id)
    if not data_source:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Data source not found")

    # This would need to be implemented per data source type
    # For now, return a placeholder
    return {
        "message": "Schema retrieval not yet implemented",
        "data_source_type": data_source.source_type,
        "table_name": table_name,
        "columns": [],
    }

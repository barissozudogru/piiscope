"""Input validation utilities for the privacy risk detection application.

This module provides validation functions for user inputs, file formats,
and configuration data to ensure data integrity and security.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import yaml
from pydantic import BaseModel, ValidationError as PydanticValidationError

from .exceptions import ValidationError


def validate_email(email: str) -> str:
    """Validate email format."""
    email = email.strip()
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(pattern, email):
        raise ValidationError("Invalid email format")
    return email.lower()


def validate_username(username: str) -> str:
    """Validate username format and length."""
    username = username.strip()
    if not username:
        raise ValidationError("Username cannot be empty")
    if len(username) < 3:
        raise ValidationError("Username must be at least 3 characters long")
    if len(username) > 50:
        raise ValidationError("Username cannot exceed 50 characters")
    if not re.match(r'^[a-zA-Z0-9_-]+$', username):
        raise ValidationError("Username can only contain letters, numbers, underscores, and hyphens")
    return username


def validate_password(password: str) -> str:
    """Validate password strength."""
    if len(password) < 8:
        raise ValidationError("Password must be at least 8 characters long")
    if len(password) > 128:
        raise ValidationError("Password cannot exceed 128 characters")
    
    checks = [
        (r'[a-z]', "Password must contain at least one lowercase letter"),
        (r'[A-Z]', "Password must contain at least one uppercase letter"),
        (r'\d', "Password must contain at least one digit"),
        (r'[!@#$%^&*(),.?":{}|<>]', "Password must contain at least one special character")
    ]
    
    for pattern, message in checks:
        if not re.search(pattern, password):
            raise ValidationError(message)
    
    return password


def validate_file_size(file_size: int, max_size: int = 2 * 1024 * 1024 * 1024) -> None:
    """Validate file size doesn't exceed limits."""
    if file_size > max_size:
        raise ValidationError(f"File size exceeds maximum allowed size of {max_size // (1024*1024)} MB")


def validate_file_extension(filename: str, allowed_extensions: List[str] = None) -> str:
    """Validate file extension is allowed."""
    if allowed_extensions is None:
        allowed_extensions = ['.csv', '.json', '.parquet', '.xlsx']
    
    file_path = Path(filename)
    extension = file_path.suffix.lower()
    
    if extension not in allowed_extensions:
        raise ValidationError(f"File extension '{extension}' not allowed. Allowed: {', '.join(allowed_extensions)}")
    
    return extension


def validate_json_data(data: Union[str, Dict]) -> Dict[str, Any]:
    """Validate and parse JSON data."""
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except json.JSONDecodeError as e:
            raise ValidationError(f"Invalid JSON format: {str(e)}")
    
    if not isinstance(data, dict):
        raise ValidationError("JSON data must be an object")
    
    return data


def validate_yaml_data(data: Union[str, Dict]) -> Dict[str, Any]:
    """Validate and parse YAML data."""
    if isinstance(data, str):
        try:
            data = yaml.safe_load(data)
        except yaml.YAMLError as e:
            raise ValidationError(f"Invalid YAML format: {str(e)}")
    
    if not isinstance(data, dict):
        raise ValidationError("YAML data must be an object")
    
    return data


def validate_profile_definition(definition: Dict[str, Any]) -> Dict[str, Any]:
    """Validate privacy detection profile definition."""
    required_fields = ['patterns', 'dictionaries', 'severity_weights']
    
    for field in required_fields:
        if field not in definition:
            raise ValidationError(f"Profile definition missing required field: {field}")
    
    # Validate patterns
    patterns = definition['patterns']
    if not isinstance(patterns, dict):
        raise ValidationError("Patterns must be a dictionary")
    
    for pattern_name, pattern_data in patterns.items():
        if not isinstance(pattern_data, dict):
            raise ValidationError(f"Pattern '{pattern_name}' must be a dictionary")
        if 'regex' not in pattern_data:
            raise ValidationError(f"Pattern '{pattern_name}' missing required 'regex' field")
        
        # Validate regex pattern
        try:
            re.compile(pattern_data['regex'])
        except re.error as e:
            raise ValidationError(f"Invalid regex in pattern '{pattern_name}': {str(e)}")
    
    # Validate dictionaries
    dictionaries = definition['dictionaries']
    if not isinstance(dictionaries, dict):
        raise ValidationError("Dictionaries must be a dictionary")
    
    for dict_name, dict_data in dictionaries.items():
        if not isinstance(dict_data, list):
            raise ValidationError(f"Dictionary '{dict_name}' must be a list")
    
    # Validate severity weights
    severity_weights = definition['severity_weights']
    if not isinstance(severity_weights, dict):
        raise ValidationError("Severity weights must be a dictionary")
    
    valid_severities = ['low', 'medium', 'high', 'critical']
    for severity, weight in severity_weights.items():
        if severity not in valid_severities:
            raise ValidationError(f"Invalid severity level: {severity}")
        if not isinstance(weight, (int, float)) or weight < 0:
            raise ValidationError(f"Severity weight for '{severity}' must be a non-negative number")
    
    return definition


def validate_scan_parameters(params: Dict[str, Any]) -> Dict[str, Any]:
    """Validate scan job parameters."""
    if 'profile_id' not in params:
        raise ValidationError("Profile ID is required")
    
    if not isinstance(params['profile_id'], int) or params['profile_id'] <= 0:
        raise ValidationError("Profile ID must be a positive integer")
    
    if 'chunk_size' in params:
        chunk_size = params['chunk_size']
        if not isinstance(chunk_size, int) or chunk_size <= 0:
            raise ValidationError("Chunk size must be a positive integer")
        if chunk_size > 10000:
            raise ValidationError("Chunk size cannot exceed 10000 rows")
    
    return params


def validate_pydantic_model(model_class: type[BaseModel], data: Dict[str, Any]) -> BaseModel:
    """Validate data against a Pydantic model."""
    try:
        return model_class(**data)
    except PydanticValidationError as e:
        error_messages = []
        for error in e.errors():
            field = " -> ".join(str(loc) for loc in error['loc'])
            message = error['msg']
            error_messages.append(f"{field}: {message}")
        
        raise ValidationError(f"Validation errors: {'; '.join(error_messages)}")


def sanitize_filename(filename: str) -> str:
    """Sanitize filename to prevent directory traversal and other security issues."""
    # Remove or replace dangerous characters
    filename = re.sub(r'[^\w\s.-]', '_', filename)
    
    # Remove directory traversal attempts
    filename = filename.replace('..', '_')
    filename = filename.replace('/', '_')
    filename = filename.replace('\\', '_')
    
    # Limit length
    if len(filename) > 255:
        name, ext = Path(filename).stem, Path(filename).suffix
        max_name_len = 255 - len(ext)
        filename = name[:max_name_len] + ext
    
    return filename.strip()


def validate_quasi_identifiers(quasi_ids: List[str], available_columns: List[str]) -> List[str]:
    """Validate quasi-identifier columns exist in the dataset."""
    invalid_columns = [col for col in quasi_ids if col not in available_columns]
    if invalid_columns:
        raise ValidationError(f"Invalid quasi-identifier columns: {', '.join(invalid_columns)}")
    
    return quasi_ids
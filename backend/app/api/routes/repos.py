"""
API routes for repository source management (PRA-37).
"""

import re
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Path
from pydantic import BaseModel, Field, validator
from sqlalchemy.orm import Session

from ...core.auth import get_current_user, require_role
from ...db.models import System, User
from ...db.session import get_db
from ...services.access_authorization_service import scoped_system_ids
from ...services.repo_service import RepoService
from ...services.ssh_service import SSHConnectionError

router = APIRouter()


def _scope_gate(db: Session, current_user: User, system_id: int) -> None:
    """PRA-281: a direct out-of-scope (or empty-scope) or nonexistent system id is
    a non-disclosing 404 — identical either way — placed BEFORE the ``System``
    lookup, any ``RepoService`` call, SSH repo read/write/sync, ``RepoSource``
    query/insert/delete, duplicate check, or serialization. So no hidden hostname,
    package-manager, repo name/URL/path/components/distribution, repo id,
    stdout/stderr snippet, or sync timestamp is ever resolved for a scoped caller.
    Tenant-wide admins (scope ``None``) are unchanged.
    """
    scope = scoped_system_ids(db, current_user)
    if scope is not None and system_id not in scope:
        raise HTTPException(status_code=404, detail="System not found")


# Repo field validation patterns
REPO_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._\- ]{0,253}[a-zA-Z0-9]$")
DISTRIBUTION_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9.\-/]+$")
COMPONENT_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9.\-]+$")


class AddRepoRequest(BaseModel):
    """Request body for adding a repository source."""

    name: str = Field(..., min_length=1, max_length=255, description="Repository name")
    url: str = Field(..., min_length=1, description="Repository URL")
    components: Optional[str] = Field(
        None, description="Repository components (e.g. 'main restricted universe')"
    )
    distribution: Optional[str] = Field(
        None, description="Distribution codename (e.g. 'jammy', 'focal')"
    )
    gpg_key_url: Optional[str] = Field(None, description="GPG key URL for verification")

    @validator("url")
    def validate_url(cls, v):  # pylint: disable=no-self-argument
        parsed = urlparse(v)
        if parsed.scheme not in ("http", "https", "ftp", "mirror"):
            raise ValueError(
                "Repository URL must use http, https, ftp, or mirror scheme"
            )
        if not parsed.netloc:
            raise ValueError("Repository URL must include a hostname")
        return v

    @validator("gpg_key_url")
    def validate_gpg_url(cls, v):  # pylint: disable=no-self-argument
        if v is None:
            return v
        parsed = urlparse(v)
        if parsed.scheme not in ("http", "https"):
            raise ValueError("GPG key URL must use http or https")
        if not parsed.netloc:
            raise ValueError("GPG key URL must include a hostname")
        return v

    @validator("distribution")
    def validate_distribution(cls, v):  # pylint: disable=no-self-argument
        if v is None:
            return v
        if not DISTRIBUTION_RE.match(v):
            raise ValueError(
                f"Invalid distribution '{v}': only alphanumeric, dots, dashes, slashes allowed"
            )
        return v

    @validator("components")
    def validate_components(cls, v):  # pylint: disable=no-self-argument
        if v is None:
            return v
        for component in v.split():
            if not COMPONENT_RE.match(component):
                raise ValueError(
                    f"Invalid component '{component}': "
                    "only alphanumeric, dots, dashes allowed"
                )
        return v


@router.get("/{system_id}", response_model=Dict[str, Any])
def list_repos(
    system_id: int = Path(..., description="The ID of the system"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List configured repository sources on a system."""
    _scope_gate(db, current_user, system_id)
    system = db.query(System).filter(System.id == system_id).first()
    if not system:
        raise HTTPException(status_code=404, detail="System not found")

    try:
        service = RepoService(db)
        return service.list_repos(system_id)
    except SSHConnectionError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error listing repos: {str(e)}"
        ) from e


@router.post("/{system_id}", response_model=Dict[str, Any])
def add_repo(
    body: AddRepoRequest,
    system_id: int = Path(..., description="The ID of the system"),
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    """Add a repository source to a system."""
    _scope_gate(db, current_user, system_id)
    system = db.query(System).filter(System.id == system_id).first()
    if not system:
        raise HTTPException(status_code=404, detail="System not found")

    try:
        service = RepoService(db)
        return service.add_repo(system_id, body.model_dump())
    except SSHConnectionError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error adding repo: {str(e)}"
        ) from e


@router.delete("/{system_id}/{repo_id}", response_model=Dict[str, Any])
def remove_repo(
    system_id: int = Path(..., description="The ID of the system"),
    repo_id: int = Path(..., description="The ID of the repo to remove"),
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    """Remove a repository source from a system."""
    # Scope-gate on the system BEFORE the repo lookup, so a hidden repo_id on a
    # hidden system is not probeable.
    _scope_gate(db, current_user, system_id)
    system = db.query(System).filter(System.id == system_id).first()
    if not system:
        raise HTTPException(status_code=404, detail="System not found")

    try:
        service = RepoService(db)
        return service.remove_repo(system_id, repo_id)
    except SSHConnectionError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error removing repo: {str(e)}"
        ) from e


@router.post("/{system_id}/sync", response_model=Dict[str, Any])
def sync_repos(
    system_id: int = Path(..., description="The ID of the system"),
    current_user: User = Depends(require_role("admin", "maintainer")),
    db: Session = Depends(get_db),
):
    """Run repository sync (apt update / yum makecache) on a system."""
    _scope_gate(db, current_user, system_id)
    system = db.query(System).filter(System.id == system_id).first()
    if not system:
        raise HTTPException(status_code=404, detail="System not found")

    try:
        service = RepoService(db)
        return service.sync_repos(system_id)
    except SSHConnectionError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error syncing repos: {str(e)}"
        ) from e


@router.get("/templates/all", response_model=Dict[str, Any])
def get_all_templates(
    current_user: User = Depends(get_current_user),  # pylint:disable=unused-argument
    db: Session = Depends(get_db),
):
    """Get all distro-specific repository templates.

    PRA-281: intentionally GLOBAL. This returns the static ``REPO_TEMPLATES``
    module constant (public distro archive repo definitions — names, public URLs,
    components); it takes no ``system_id`` and reads no host, tenant, credential,
    mirror, or secret data, so it is distro taxonomy, not fleet inventory.
    """
    service = RepoService(db)
    return service.get_templates()


@router.get("/templates/{system_id}", response_model=Dict[str, Any])
def get_system_templates(
    system_id: int = Path(..., description="The ID of the system"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Get repository templates for a specific system's distro."""
    # PRA-281: this derives templates from the target host's distro, so scope-gate
    # the direct system id BEFORE the System/Distro lookup or template response.
    _scope_gate(db, current_user, system_id)
    system = db.query(System).filter(System.id == system_id).first()
    if not system:
        raise HTTPException(status_code=404, detail="System not found")

    try:
        service = RepoService(db)
        return service.get_templates(system_id=system_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Error getting templates: {str(e)}"
        ) from e

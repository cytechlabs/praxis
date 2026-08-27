"""Shared tag resolution for system registration.

Registration, update and guided onboarding all let an operator label a host by
name rather than by tag id. Resolving those names, creating the ones that do not
exist yet, and replacing a host's associations are the same operation in all
three places, so they live here rather than being written three times with three
subtly different ideas of what a duplicate or a blank name means.
"""

from __future__ import annotations

from typing import Iterable, List

from sqlalchemy.orm import Session

from ..db.models import System, Tag, system_tag


def resolve_tags(db: Session, names: Iterable[str], *, created_by: int) -> List[Tag]:
    """Return tag rows for ``names``, creating any that do not exist.

    Flushes so callers can use the ids inside the same transaction. Blank names
    are dropped and duplicates collapse, so the caller does not have to
    pre-clean a list an operator typed.
    """
    tags: List[Tag] = []
    seen: set = set()
    for raw in names:
        name = (raw or "").strip()
        if not name or name in seen:
            continue
        seen.add(name)
        tag = db.query(Tag).filter(Tag.name == name).first()
        if tag is None:
            tag = Tag(name=name, created_by=created_by)
            db.add(tag)
            db.flush()
        tags.append(tag)
    return tags


def set_system_tags(
    db: Session, system: System, names: Iterable[str], *, created_by: int
) -> List[Tag]:
    """Replace ``system``'s tags with exactly ``names``.

    A replacement, not a merge: supplying a list is how an operator says what
    the host's labels are, so a tag left out of that list is removed. Callers
    that mean "leave tags alone" must not call this at all.
    """
    tags = resolve_tags(db, names, created_by=created_by)
    db.execute(system_tag.delete().where(system_tag.c.system_id == system.id))
    for tag in tags:
        db.execute(system_tag.insert().values(system_id=system.id, tag_id=tag.id))
    return tags

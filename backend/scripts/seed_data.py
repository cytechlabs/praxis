"""Seed initial data for groups, distros, and roles after migrations."""

from datetime import date

from app.db.models import Distro, Group, Role
from app.db.session import SessionLocal


def seed_data():
    db = SessionLocal()

    # Seed default group
    if not db.query(Group).filter(Group.name == "All Systems").first():
        db.add(
            Group(
                id=1,
                name="All Systems",
                description="Default group containing all systems",
            )
        )
        db.commit()
        print("Default 'All Systems' group created.")

    # Seed distros (upsert — adds new ones on every startup, never duplicates)
    distro_definitions = [
        ("Ubuntu", "20.04", date(2020, 4, 23), date(2030, 4, 23)),
        ("Ubuntu", "22.04", date(2022, 4, 21), date(2032, 4, 21)),
        ("Ubuntu", "24.04", date(2024, 4, 25), date(2034, 4, 25)),
        ("AlmaLinux", "8", date(2021, 3, 30), date(2029, 3, 1)),
        ("AlmaLinux", "9", date(2022, 5, 26), date(2032, 5, 31)),
        ("AlmaLinux", "10", date(2024, 12, 9), date(2034, 11, 30)),
        ("RHEL", "8", date(2019, 5, 7), date(2029, 5, 31)),
        ("RHEL", "9", date(2022, 5, 17), date(2032, 5, 31)),
        ("Rocky Linux", "8", date(2021, 6, 21), date(2029, 5, 31)),
        ("Rocky Linux", "9", date(2022, 7, 14), date(2032, 5, 31)),
        ("Debian", "11", date(2021, 8, 14), date(2026, 6, 30)),
        ("Debian", "12", date(2023, 6, 10), date(2028, 6, 10)),
        ("CentOS Stream", "9", date(2021, 12, 3), date(2027, 5, 31)),
        ("Oracle Linux", "8", date(2019, 7, 19), date(2029, 7, 1)),
        ("Oracle Linux", "9", date(2022, 7, 6), date(2032, 7, 1)),
    ]
    added = 0
    for name, version, release, eol in distro_definitions:
        exists = (
            db.query(Distro)
            .filter(Distro.name == name, Distro.version == version)
            .first()
        )
        if not exists:
            db.add(
                Distro(
                    name=name,
                    version=version,
                    release_date=release,
                    end_of_life_date=eol,
                )
            )
            added += 1
    if added:
        db.commit()
        print(f"{added} new distro(s) added.")

    # Seed roles
    for role_name, role_desc in [
        ("admin", "Full access to everything"),
        ("maintainer", "Manage systems, credentials, packages, jobs, SSH, vault"),
        ("auditor", "Read-only access to all data"),
    ]:
        if not db.query(Role).filter(Role.name == role_name).first():
            db.add(Role(name=role_name, description=role_desc))
            db.commit()
            print(f"Role '{role_name}' created.")

    db.close()


if __name__ == "__main__":
    seed_data()

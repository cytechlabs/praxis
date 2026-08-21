from setuptools import find_packages, setup

setup(
    name="app",
    version="1.0.0",
    packages=find_packages(),
    # Runtime shell assets executed by the backend. They are declared here
    # so the wheel and the source distribution carry the same files an
    # editable checkout exposes; the readers resolve them through the
    # package resource API.
    package_data={
        "app.api.routes": ["_assets/*.sh"],
        "app.services": ["_assets/*.sh"],
    },
    install_requires=[
        "fastapi==0.109.0",
        "uvicorn==0.27.0",
        "sqlalchemy==2.0.51",
        "alembic==1.18.5",
        "psycopg2-binary==2.9.12",
        "pydantic-settings==2.1.0",
    ],
    entry_points={
        "console_scripts": [
            # PRA-160 slice #5-a: register the operator-facing
            # ``praxis-airgap`` command so ``inspect`` / ``verify``
            # subcommands resolve to a named binary inside the
            # backend image. ``python -m app.cli.airgap`` keeps
            # working as a fallback.
            "praxis-airgap=app.cli.airgap:main",
        ],
    },
)

from setuptools import find_packages, setup

setup(
    name="app",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "fastapi==0.141.1",
        "uvicorn==0.52.1",
        "sqlalchemy==2.0.51",
        "alembic==1.19.0",
        "psycopg2-binary==2.9.12",
        "pydantic-settings==2.15.0",
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

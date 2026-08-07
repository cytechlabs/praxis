"""``app.ee`` — public-core boundary for the optional paid ``praxis_ee`` package.

This package contains **no** closed-source or paid logic. It only defines the
loader seam (:func:`app.ee.loader.load_ee`) that a separately-distributed
``praxis_ee`` package plugs into at startup. See :mod:`app.ee.loader` for the
``register_ee`` contract and failure policy.
"""

from app.ee.loader import EELoaderError, load_ee

__all__ = ["load_ee", "EELoaderError"]

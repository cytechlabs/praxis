"""PRA-266: the public app links to the Praxis website buy page with THIS
install's server-owned instance_id prefilled. The app holds no Paddle price IDs,
starts no checkout, and never calls the EE bridge — the website does all of that.
"""

from urllib.parse import parse_qs, quote, urlparse

from app.services import license_service


def test_buy_url_uses_server_owned_instance_id(db, monkeypatch):
    monkeypatch.delenv(license_service.BUY_LICENSE_URL_ENV, raising=False)
    url = license_service.buy_license_url(db)
    iid = license_service.get_or_create_instance_id(db)
    parsed = urlparse(url)
    assert parsed.scheme == "https"  # default is the production buy page
    assert parse_qs(parsed.query)["instance_id"] == [iid]


def test_buy_url_url_encodes_install_id(db, monkeypatch):
    monkeypatch.delenv(license_service.BUY_LICENSE_URL_ENV, raising=False)
    # Force an id with characters that MUST be percent-encoded.
    license_service._set_setting(db, license_service.INSTANCE_ID_KEY, "a b/c?d&e")
    db.commit()
    url = license_service.buy_license_url(db)
    assert "instance_id=a%20b%2Fc%3Fd%26e" in url
    # And it round-trips back to the raw value.
    assert parse_qs(urlparse(url).query)["instance_id"] == ["a b/c?d&e"]


def test_buy_url_env_override_and_query_separator(db, monkeypatch):
    iid = license_service.get_or_create_instance_id(db)
    # No existing query -> '?'.
    monkeypatch.setenv(
        license_service.BUY_LICENSE_URL_ENV, "https://buy.example.test/pricing"
    )
    assert license_service.buy_license_url(db) == (
        f"https://buy.example.test/pricing?instance_id={quote(iid, safe='')}"
    )
    # Existing query -> '&'.
    monkeypatch.setenv(
        license_service.BUY_LICENSE_URL_ENV, "https://buy.example.test/pricing?ref=x"
    )
    assert license_service.buy_license_url(db) == (
        f"https://buy.example.test/pricing?ref=x&instance_id={quote(iid, safe='')}"
    )


def test_app_holds_no_paddle_price_ids_or_checkout():
    # The public app must not expose a plan catalog, checkout starter, or price IDs.
    for name in (
        "create_checkout",
        "list_checkout_plans",
        "_load_checkout_plans",
        "CHECKOUT_PLANS",
        "_DEFAULT_CHECKOUT_PLANS",
        "CHECKOUT_PLANS_ENV",
        "CheckoutError",
    ):
        assert not hasattr(license_service, name), f"{name} should be removed"
    # No Paddle price IDs anywhere in the module source.
    import inspect

    src = inspect.getsource(license_service)
    assert "pri_01ky" not in src

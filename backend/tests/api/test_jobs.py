"""Integration tests for the jobs routes."""


def _create_job(authed_client, **overrides):
    body = {
        "name": "nightly-scan",
        "description": "scan all systems",
        "job_type": "package_scan",
        "target_type": "all",
    }
    body.update(overrides)
    return authed_client.post("/jobs", json=body)


def test_create_job(authed_client):
    res = _create_job(authed_client)
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["status"] == "success"
    assert body["job"]["name"] == "nightly-scan"
    assert body["job"]["job_type"] == "package_scan"


def test_list_jobs(authed_client):
    _create_job(authed_client, name="list-job-a")
    _create_job(authed_client, name="list-job-b")

    res = authed_client.get("/jobs")
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "success"
    assert body["total"] >= 2
    names = [j["name"] for j in body["jobs"]]
    assert "list-job-a" in names
    assert "list-job-b" in names


def test_get_job_detail(authed_client):
    created = _create_job(authed_client, name="detail-job").json()
    job_id = created["job"]["id"]

    res = authed_client.get(f"/jobs/{job_id}")
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "success"
    assert body["job"]["id"] == job_id
    assert body["job"]["name"] == "detail-job"


def test_get_job_404(authed_client):
    res = authed_client.get("/jobs/999999")
    assert res.status_code == 404


def test_list_failed_jobs_shape(authed_client):
    res = authed_client.get("/jobs/failed")
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "success"
    assert "total" in body
    assert "limit" in body
    assert "offset" in body
    assert isinstance(body["history"], list)


def test_list_all_history_shape(authed_client):
    res = authed_client.get("/jobs/history")
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "success"
    assert isinstance(body["history"], list)
    assert "total" in body


def test_delete_job(authed_client):
    created = _create_job(authed_client, name="delete-me").json()
    job_id = created["job"]["id"]

    res = authed_client.delete(f"/jobs/{job_id}")
    assert res.status_code == 200
    assert res.json()["status"] == "success"

    # Confirm gone
    res = authed_client.get(f"/jobs/{job_id}")
    assert res.status_code == 404


def test_create_job_invalid_type_rejected(authed_client):
    res = _create_job(authed_client, job_type="not-a-real-type")
    assert res.status_code == 400

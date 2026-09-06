from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture(autouse=True)
def isolate_github_credentials(monkeypatch, request):
    """Prevent ambient GitHub credentials from enabling live test mutations."""
    if request.node.get_closest_marker("network") is not None:
        return

    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)


@pytest.fixture
def mock_github_client():
    """Provide a deterministic PyGithub client for delivery-path tests."""
    with patch("app.github.pull_requests.Github") as github_class:
        repository = MagicMock()
        repository.default_branch = "main"
        repository.get_pulls.return_value = []

        default_branch = MagicMock()
        default_branch.commit.sha = "base-commit-sha"

        def get_branch(name):
            if name == "main":
                return default_branch
            raise RuntimeError("branch does not exist")

        repository.get_branch.side_effect = get_branch
        repository.get_contents.return_value = None
        repository.create_pull.return_value.html_url = "https://github.com/test/repo/pull/123"

        github_client = github_class.return_value
        github_client.get_repo.return_value = repository
        yield github_class, github_client, repository

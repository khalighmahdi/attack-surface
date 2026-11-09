"""Authenticated Scanning Module — Cookie, Token, Header, and Session management.

Supports:
- Cookie-based authentication (import from browser, manual entry)
- Bearer token / JWT authentication
- API Key authentication (header, query param)
- Form-based login with session persistence
- OAuth2 client credentials flow
- Session replay for authenticated scans
"""
from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

logger = logging.getLogger("AttackSurface.Auth")


@dataclass
class AuthConfig:
    """Authentication configuration for a target."""
    name: str
    auth_type: str  # cookie, bearer, api_key, form, oauth2
    target_domain: str
    credentials: Dict[str, Any]  # varies by auth_type
    headers: Dict[str, str]
    cookies: Dict[str, str]
    session_file: Optional[str]
    verified: bool
    verified_at: Optional[str]
    expires_at: Optional[str]


class AuthManager:
    """Manage authentication configurations and sessions."""

    def __init__(self, storage_dir: Path = None):
        self.storage_dir = storage_dir or Path(os.path.expanduser("~/.attack_surface/auth"))
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.configs_file = self.storage_dir / "auth_configs.json"
        self.configs: Dict[str, AuthConfig] = {}
        self._load()

    def _load(self):
        try:
            if self.configs_file.exists():
                data = json.loads(self.configs_file.read_text())
                self.configs = {k: AuthConfig(**v) for k, v in data.items()}
        except Exception as e:
            logger.warning("Failed to load auth configs: %s", e)
            self.configs = {}

    def _save(self):
        try:
            data = {k: asdict(v) for k, v in self.configs.items()}
            self.configs_file.write_text(json.dumps(data, indent=2))
        except Exception as e:
            logger.warning("Failed to save auth configs: %s", e)

    def add_cookie_auth(self, name: str, domain: str, cookies: Dict[str, str],
                        headers: Dict[str, str] = None) -> AuthConfig:
        """Add cookie-based authentication."""
        config = AuthConfig(
            name=name,
            auth_type="cookie",
            target_domain=domain,
            credentials={},
            headers=headers or {},
            cookies=cookies,
            session_file=None,
            verified=False,
            verified_at=None,
            expires_at=None
        )
        self.configs[name] = config
        self._save()
        return config

    def add_bearer_auth(self, name: str, domain: str, token: str,
                        header_name: str = "Authorization") -> AuthConfig:
        """Add Bearer token authentication."""
        config = AuthConfig(
            name=name,
            auth_type="bearer",
            target_domain=domain,
            credentials={"token": token, "header": header_name},
            headers={header_name: f"Bearer {token}"},
            cookies={},
            session_file=None,
            verified=False,
            verified_at=None,
            expires_at=None
        )
        self.configs[name] = config
        self._save()
        return config

    def add_api_key_auth(self, name: str, domain: str, api_key: str,
                         header_name: str = "X-API-Key", query_param: str = None) -> AuthConfig:
        """Add API Key authentication."""
        headers = {header_name: api_key}
        creds = {"api_key": api_key, "header": header_name}
        if query_param:
            creds["query_param"] = query_param
        config = AuthConfig(
            name=name,
            auth_type="api_key",
            target_domain=domain,
            credentials=creds,
            headers=headers,
            cookies={},
            session_file=None,
            verified=False,
            verified_at=None,
            expires_at=None
        )
        self.configs[name] = config
        self._save()
        return config

    def add_form_auth(self, name: str, domain: str, login_url: str,
                      username: str, password: str,
                      username_field: str = "username", password_field: str = "password",
                      extra_fields: Dict[str, str] = None) -> AuthConfig:
        """Add form-based authentication with session persistence."""
        config = AuthConfig(
            name=name,
            auth_type="form",
            target_domain=domain,
            credentials={
                "login_url": login_url,
                "username": username,
                "password": password,
                "username_field": username_field,
                "password_field": password_field,
                "extra_fields": extra_fields or {}
            },
            headers={},
            cookies={},
            session_file=str(self.storage_dir / f"{name}_session.cookies"),
            verified=False,
            verified_at=None,
            expires_at=None
        )
        self.configs[name] = config
        self._save()
        return config

    def add_oauth2_auth(self, name: str, domain: str, client_id: str,
                        client_secret: str, token_url: str,
                        scope: str = "") -> AuthConfig:
        """Add OAuth2 client credentials flow."""
        config = AuthConfig(
            name=name,
            auth_type="oauth2",
            target_domain=domain,
            credentials={
                "client_id": client_id,
                "client_secret": client_secret,
                "token_url": token_url,
                "scope": scope
            },
            headers={},
            cookies={},
            session_file=str(self.storage_dir / f"{name}_oauth.json"),
            verified=False,
            verified_at=None,
            expires_at=None
        )
        self.configs[name] = config
        self._save()
        return config

    def import_cookies_from_browser(self, name: str, domain: str,
                                     browser: str = "chrome") -> AuthConfig:
        """Import cookies from browser (requires browser_cookie3)."""
        try:
            import browser_cookie3
            cj = getattr(browser_cookie3, browser)(domain_name=domain)
            cookies = {cookie.name: cookie.value for cookie in cj}
            return self.add_cookie_auth(name, domain, cookies)
        except ImportError:
            logger.error("browser_cookie3 not installed: pip install browser_cookie3")
            raise
        except Exception as e:
            logger.error("Failed to import cookies: %s", e)
            raise

    def get_auth_session(self, name: str) -> Optional[requests.Session]:
        """Get a verified requests.Session for the auth config."""
        config = self.configs.get(name)
        if not config:
            return None

        session = requests.Session()
        session.headers.update(config.headers)
        session.cookies.update(config.cookies)

        if config.auth_type == "form" and not config.verified:
            self._verify_form_session(config, session)
        elif config.auth_type == "oauth2" and (not config.verified or self._token_expired(config)):
            self._refresh_oauth2_token(config, session)

        return session

    def _verify_form_session(self, config: AuthConfig, session: requests.Session):
        """Perform form login and save session cookies."""
        try:
            login_data = {
                config.credentials["username_field"]: config.credentials["username"],
                config.credentials["password_field"]: config.credentials["password"],
                **config.credentials.get("extra_fields", {})
            }
            resp = session.post(config.credentials["login_url"], data=login_data, timeout=15)
            if resp.status_code in (200, 302) and session.cookies:
                config.cookies = dict(session.cookies)
                config.verified = True
                config.verified_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                # Save cookies to file
                if config.session_file:
                    import pickle
                    with open(config.session_file, "wb") as f:
                        pickle.dump(dict(session.cookies), f)
                self._save()
                logger.info("Form auth verified for %s", config.name)
        except Exception as e:
            logger.warning("Form auth verification failed: %s", e)

    def _token_expired(self, config: AuthConfig) -> bool:
        if not config.expires_at:
            return True
        return time.time() > time.mktime(time.strptime(config.expires_at, "%Y-%m-%dT%H:%M:%SZ"))

    def _refresh_oauth2_token(self, config: AuthConfig, session: requests.Session):
        """Refresh OAuth2 access token."""
        try:
            data = {
                "grant_type": "client_credentials",
                "client_id": config.credentials["client_id"],
                "client_secret": config.credentials["client_secret"],
            }
            if config.credentials.get("scope"):
                data["scope"] = config.credentials["scope"]

            resp = session.post(config.credentials["token_url"], data=data, timeout=15)
            if resp.status_code == 200:
                token_data = resp.json()
                access_token = token_data.get("access_token")
                expires_in = token_data.get("expires_in", 3600)
                if access_token:
                    config.headers["Authorization"] = f"Bearer {access_token}"
                    config.credentials["token"] = access_token
                    config.expires_at = time.strftime(
                        "%Y-%m-%dT%H:%M:%SZ",
                        time.gmtime(time.time() + expires_in - 60)
                    )
                    config.verified = True
                    config.verified_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                    self._save()
                    logger.info("OAuth2 token refreshed for %s", config.name)
        except Exception as e:
            logger.warning("OAuth2 token refresh failed: %s", e)

    def list_configs(self) -> List[AuthConfig]:
        return list(self.configs.values())

    def delete_config(self, name: str):
        if name in self.configs:
            del self.configs[name]
            self._save()

    def export_config(self, name: str, export_path: Path, include_secrets: bool = False):
        """Export auth config to file (optionally without secrets)."""
        config = self.configs.get(name)
        if not config:
            return
        data = asdict(config)
        if not include_secrets:
            # Redact sensitive fields
            if config.auth_type == "bearer":
                data["credentials"]["token"] = "***REDACTED***"
            elif config.auth_type == "api_key":
                data["credentials"]["api_key"] = "***REDACTED***"
            elif config.auth_type == "form":
                data["credentials"]["password"] = "***REDACTED***"
            elif config.auth_type == "oauth2":
                data["credentials"]["client_secret"] = "***REDACTED***"
        export_path.write_text(json.dumps(data, indent=2))
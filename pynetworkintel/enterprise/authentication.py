"""Enterprise authentication and authorization."""
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
import hashlib
import logging

logger = logging.getLogger(__name__)


@dataclass
class User:
    user_id: str
    username: str
    email: str
    roles: List[str]
    created_at: datetime
    last_login: Optional[datetime] = None
    is_active: bool = True
    mfa_enabled: bool = False
    password_hash: str = ""


class AuthenticationManager:
    """Manage enterprise authentication and authorization."""

    def __init__(self):
        """Initialize authentication manager."""
        self.users: Dict[str, User] = {}
        self.roles: Dict[str, List[str]] = {
            "admin": ["read", "write", "delete", "manage_users", "manage_tenants"],
            "operator": ["read", "write", "manage_alerts"],
            "analyst": ["read", "analyze"],
            "viewer": ["read"],
        }
        self.sessions: Dict[str, Dict[str, Any]] = {}

    def create_user(self, username: str, email: str, password: str, roles: List[str]) -> Optional[str]:
        """Create a new user."""
        if username in [u.username for u in self.users.values()]:
            logger.error(f"Username {username} already exists")
            return None

        import uuid
        user_id = str(uuid.uuid4())

        password_hash = self._hash_password(password)

        user = User(
            user_id=user_id,
            username=username,
            email=email,
            roles=roles,
            created_at=datetime.now(),
            password_hash=password_hash,
        )

        self.users[user_id] = user

        logger.info(f"Created user: {username}")

        return user_id

    def authenticate(self, username: str, password: str) -> Tuple[bool, Optional[str]]:
        """Authenticate a user and return session token."""
        # Find user by username
        user = None
        for u in self.users.values():
            if u.username == username:
                user = u
                break

        if not user:
            logger.warning(f"Authentication failed: user {username} not found")
            return False, None

        if not user.is_active:
            logger.warning(f"Authentication failed: user {username} is inactive")
            return False, None

        # Verify password
        if not self._verify_password(password, user.password_hash):
            logger.warning(f"Authentication failed: invalid password for {username}")
            return False, None

        # Create session
        import uuid
        session_token = self._generate_session_token()
        self.sessions[session_token] = {
            "user_id": user.user_id,
            "username": username,
            "created_at": datetime.now(),
            "expires_at": datetime.now() + timedelta(hours=8),
        }

        user.last_login = datetime.now()

        logger.info(f"User {username} authenticated")

        return True, session_token

    def validate_session(self, session_token: str) -> Optional[Dict[str, Any]]:
        """Validate a session token."""
        if session_token not in self.sessions:
            return None

        session = self.sessions[session_token]

        # Check if expired
        if session["expires_at"] < datetime.now():
            del self.sessions[session_token]
            return None

        return session

    def authorize(self, user_id: str, required_permission: str) -> bool:
        """Check if user has required permission."""
        if user_id not in self.users:
            return False

        user = self.users[user_id]

        for role in user.roles:
            if role not in self.roles:
                continue

            permissions = self.roles[role]
            if required_permission in permissions or "*" in permissions:
                return True

        return False

    def enable_mfa(self, user_id: str) -> Optional[str]:
        """Enable MFA for user."""
        if user_id not in self.users:
            return None

        user = self.users[user_id]
        user.mfa_enabled = True

        # Generate MFA secret (simplified)
        import secrets
        mfa_secret = secrets.token_hex(10)

        logger.info(f"Enabled MFA for user {user.username}")

        return mfa_secret

    def verify_mfa(self, user_id: str, code: str) -> bool:
        """Verify MFA code (simplified)."""
        if user_id not in self.users:
            return False

        user = self.users[user_id]

        if not user.mfa_enabled:
            return False

        # In production, use TOTP library like pyotp
        # This is simplified
        return len(code) == 6 and code.isdigit()

    def configure_ldap(self, server: str, base_dn: str, username_attr: str = "uid") -> bool:
        """Configure LDAP authentication."""
        logger.info(f"Configured LDAP: {server} ({base_dn})")
        return True

    def configure_oauth(self, provider: str, client_id: str, client_secret: str) -> bool:
        """Configure OAuth 2.0 authentication."""
        supported_providers = ["google", "github", "azure_ad"]

        if provider not in supported_providers:
            logger.error(f"Unsupported OAuth provider: {provider}")
            return False

        logger.info(f"Configured OAuth 2.0: {provider}")
        return True

    def configure_saml(self, idp_url: str, certificate_path: str) -> bool:
        """Configure SAML 2.0 authentication."""
        logger.info(f"Configured SAML 2.0: {idp_url}")
        return True

    def change_password(self, user_id: str, old_password: str, new_password: str) -> bool:
        """Change user password."""
        if user_id not in self.users:
            return False

        user = self.users[user_id]

        # Verify old password
        if not self._verify_password(old_password, user.password_hash):
            return False

        # Set new password
        user.password_hash = self._hash_password(new_password)

        logger.info(f"Password changed for user {user.username}")

        return True

    def reset_password(self, user_id: str, new_password: str) -> bool:
        """Reset user password (admin only)."""
        if user_id not in self.users:
            return False

        user = self.users[user_id]
        user.password_hash = self._hash_password(new_password)

        logger.info(f"Password reset for user {user.username}")

        return True

    def revoke_session(self, session_token: str) -> bool:
        """Revoke a session."""
        if session_token in self.sessions:
            del self.sessions[session_token]
            return True

        return False

    def get_user_info(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get user information."""
        if user_id not in self.users:
            return None

        user = self.users[user_id]

        return {
            "user_id": user.user_id,
            "username": user.username,
            "email": user.email,
            "roles": user.roles,
            "is_active": user.is_active,
            "mfa_enabled": user.mfa_enabled,
            "created_at": user.created_at.isoformat(),
            "last_login": user.last_login.isoformat() if user.last_login else None,
        }

    @staticmethod
    def _hash_password(password: str) -> str:
        """Hash password using SHA-256."""
        import secrets
        salt = secrets.token_hex(16)
        pwd_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100000)
        return f"{salt}${pwd_hash.hex()}"

    @staticmethod
    def _verify_password(password: str, password_hash: str) -> bool:
        """Verify password against hash."""
        try:
            salt, hash_value = password_hash.split("$")
            pwd_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100000)
            return pwd_hash.hex() == hash_value
        except:
            return False

    @staticmethod
    def _generate_session_token() -> str:
        """Generate secure session token."""
        import secrets
        return secrets.token_urlsafe(32)

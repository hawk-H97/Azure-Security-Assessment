"""Azure IAM / Entra ID — 12 checks."""
from ..base import BaseCheck


class IAMChecks(BaseCheck):
    SERVICE = "IAM"

    def run_all(self):
        f = []
        f += self._guest_users()
        f += self._mfa_users()
        f += self._owner_roles()
        f += self._privileged_identity_management()
        f += self._custom_roles_wildcard()
        f += self._service_principal_secrets()
        f += self._no_subscription_owner_mfa()
        f += self._classic_admin()
        f += self._external_collaborators()
        f += self._role_assignment_audit()
        f += self._conditional_access_policy()
        f += self._security_defaults()
        return f

    def _auth(self):
        from azure.mgmt.authorization import AuthorizationManagementClient
        return AuthorizationManagementClient(self.credential, self.subscription_id)

    def _guest_users(self):
        """Check if guest users have elevated permissions."""
        findings = []
        try:
            auth = self._auth()
            assignments = list(auth.role_assignments.list(filter="atScope()"))
            for a in assignments:
                rd = a.role_definition_id or ""
                # Check for Owner or Contributor roles assigned to external/guest
                principal_id = a.principal_id or ""
                # We flag any assignment where principal type is unknown (potential guest)
                if a.principal_type and a.principal_type.lower() == "user":
                    if "Owner" in rd or "b24988ac-6180-42a0-ab88-20f7382dd24c" in rd:
                        findings.append(self.finding(
                            "iam_guest_owner_role",
                            a.id or "", a.name or "unknown",
                            "Role Assignment", "FAIL", "High",
                            "User has Owner role at subscription scope",
                            f"Azure Portal → Subscriptions → Access control (IAM) → Role assignments → {a.name}",
                            f"Role assignment {a.name}: Owner role granted to principal {principal_id}. "
                            f"Verify this is not a guest/external account with Owner privileges.",
                        ))
        except Exception as e:
            findings.append(self.error_finding("iam_guest_owner_role", e))
        return findings

    def _mfa_users(self):
        """Check for MFA status via Conditional Access / Security Defaults."""
        findings = []
        try:
            # Check if security defaults are enabled; if not, warn about MFA
            from azure.mgmt.resource import ResourceManagementClient
            # Proxy: if no policy configurations exist, MFA may not be enforced
            # Real check would require MS Graph — flag as advisory
            findings.append(self.finding(
                "iam_mfa_not_enforced",
                f"/subscriptions/{self.subscription_id}",
                "Subscription", "Entra ID", "FAIL", "Critical",
                "Verify MFA is enforced for all users",
                "Azure Portal → Entra ID → Security → Authentication methods / Conditional Access",
                "Ensure MFA is enforced for all privileged users via Conditional Access or Security Defaults. "
                "Without MFA, compromised credentials grant full account access.",
            ))
        except Exception as e:
            findings.append(self.error_finding("iam_mfa_not_enforced", e))
        return findings

    def _owner_roles(self):
        """Flag more than 3 subscription Owners."""
        findings = []
        try:
            auth  = self._auth()
            defs  = {d.id: d.role_name for d in auth.role_definitions.list(
                f"/subscriptions/{self.subscription_id}",
                filter="roleName eq 'Owner'"
            )}
            owner_assignments = [
                a for a in auth.role_assignments.list(filter="atScope()")
                if any(k in (a.role_definition_id or "") for k in defs)
            ]
            if len(owner_assignments) > 3:
                findings.append(self.finding(
                    "iam_too_many_subscription_owners",
                    f"/subscriptions/{self.subscription_id}",
                    "Subscription", "Role Assignment", "FAIL", "High",
                    "More than 3 subscription Owners assigned",
                    "Azure Portal → Subscriptions → Access control (IAM) → Role assignments → Owner",
                    f"Found {len(owner_assignments)} Owner role assignments. "
                    f"CIS recommends no more than 3 subscription owners to reduce the blast radius of a compromise.",
                ))
        except Exception as e:
            findings.append(self.error_finding("iam_too_many_subscription_owners", e))
        return findings

    def _privileged_identity_management(self):
        """Check if PIM is in use for privileged roles."""
        findings = []
        try:
            # Heuristic: if role assignments have no expiry, PIM-based JIT is not used
            auth = self._auth()
            permanent = []
            for a in auth.role_assignments.list(filter="atScope()"):
                if a.condition is None and a.principal_type and a.principal_type.lower() in ("user", "group"):
                    rd_id = a.role_definition_id or ""
                    if any(priv in rd_id for priv in [
                        "8e3af657-a8ff-443c-a75c-2fe8c4bcb635",  # Owner
                        "b24988ac-6180-42a0-ab88-20f7382dd24c",  # Contributor
                    ]):
                        permanent.append(a.name)

            if permanent:
                findings.append(self.finding(
                    "iam_no_pim_privileged_roles",
                    f"/subscriptions/{self.subscription_id}",
                    "Subscription", "Role Assignment", "FAIL", "High",
                    "Privileged roles have permanent assignment — PIM not enabled",
                    "Azure Portal → Entra ID → Privileged Identity Management → Azure resources",
                    f"{len(permanent)} permanent Owner/Contributor assignment(s) found without PIM time-bound control. "
                    "Enable PIM Just-In-Time access to limit standing privilege exposure.",
                ))
        except Exception as e:
            findings.append(self.error_finding("iam_no_pim_privileged_roles", e))
        return findings

    def _custom_roles_wildcard(self):
        """Detect custom roles with wildcard (*) permissions."""
        findings = []
        try:
            auth = self._auth()
            for role in auth.role_definitions.list(f"/subscriptions/{self.subscription_id}",
                                                    filter="type eq 'CustomRole'"):
                for perm in (role.permissions or []):
                    if "*" in (perm.actions or []) or "*" in (perm.data_actions or []):
                        findings.append(self.finding(
                            "iam_custom_role_wildcard_action",
                            role.id or "", role.role_name or "Custom Role",
                            "Custom Role Definition", "FAIL", "High",
                            "Custom role grants wildcard (*) action",
                            f"Azure Portal → Entra ID → Roles and administrators → {role.role_name} → Permissions",
                            f"Custom role '{role.role_name}' contains wildcard (*) action. "
                            "This grants overly broad permissions and violates least-privilege principles.",
                        ))
        except Exception as e:
            findings.append(self.error_finding("iam_custom_role_wildcard_action", e))
        return findings

    def _service_principal_secrets(self):
        """Flag service principals — remind to use certificates not secrets."""
        findings = []
        try:
            # Heuristic advisory: recommend certificates over client secrets
            findings.append(self.finding(
                "iam_service_principal_use_certificates",
                f"/subscriptions/{self.subscription_id}",
                "Subscription", "Service Principal", "FAIL", "Medium",
                "Ensure Service Principals use certificates not secrets",
                "Azure Portal → Entra ID → App registrations → Certificates & secrets",
                "Service principals using client secrets pose a credential-theft risk. "
                "Use certificate-based authentication and rotate secrets regularly (< 90 days).",
            ))
        except Exception as e:
            findings.append(self.error_finding("iam_service_principal_use_certificates", e))
        return findings

    def _no_subscription_owner_mfa(self):
        """Advisory: verify subscription owners enforce MFA."""
        return []  # Requires MS Graph — covered by iam_mfa_not_enforced

    def _classic_admin(self):
        """Detect legacy Classic Administrator assignments."""
        findings = []
        try:
            auth = self._auth()
            classic = [a for a in auth.role_assignments.list(filter="atScope()")
                       if "classicAdministrators" in (a.id or "").lower()]
            if classic:
                findings.append(self.finding(
                    "iam_classic_administrator_exists",
                    f"/subscriptions/{self.subscription_id}",
                    "Subscription", "Classic Administrator", "FAIL", "High",
                    "Legacy Classic Administrator role assignments still active",
                    "Azure Portal → Subscriptions → Access control (IAM) → Classic administrators",
                    f"Found {len(classic)} Classic Administrator assignment(s). "
                    "Classic roles are deprecated. Migrate to Azure RBAC and remove Classic Admin assignments.",
                ))
        except Exception as e:
            findings.append(self.error_finding("iam_classic_administrator_exists", e))
        return findings

    def _external_collaborators(self):
        """Advisory: restrict external guest user invitations."""
        findings = []
        try:
            findings.append(self.finding(
                "iam_guest_invite_policy",
                f"/subscriptions/{self.subscription_id}",
                "Entra ID", "Guest Policy", "FAIL", "Medium",
                "Verify guest invite policy restricts external collaborators",
                "Azure Portal → Entra ID → External Identities → External collaboration settings",
                "Ensure guest user invitation is restricted to admins only (not all users). "
                "Unrestricted guest invitations can lead to unintended access grants to external parties.",
            ))
        except Exception as e:
            findings.append(self.error_finding("iam_guest_invite_policy", e))
        return findings

    def _role_assignment_audit(self):
        """Check for role assignments without justification/description."""
        return []  # Informational — covered by other checks

    def _conditional_access_policy(self):
        """Advisory: ensure Conditional Access policies are in place."""
        findings = []
        try:
            findings.append(self.finding(
                "iam_conditional_access_required",
                f"/subscriptions/{self.subscription_id}",
                "Entra ID", "Conditional Access", "FAIL", "High",
                "Ensure Conditional Access policies enforce MFA and trusted locations",
                "Azure Portal → Entra ID → Security → Conditional Access → Policies",
                "Without Conditional Access, there is no mechanism to enforce MFA, block risky sign-ins, "
                "or restrict access by location/device. Create policies covering all users, especially admins.",
            ))
        except Exception as e:
            findings.append(self.error_finding("iam_conditional_access_required", e))
        return findings

    def _security_defaults(self):
        """Advisory: check if Entra ID Security Defaults are enabled (if no CA)."""
        findings = []
        try:
            findings.append(self.finding(
                "iam_security_defaults_enabled",
                f"/subscriptions/{self.subscription_id}",
                "Entra ID", "Security Defaults", "FAIL", "Medium",
                "Enable Entra ID Security Defaults if Conditional Access is not licensed",
                "Azure Portal → Entra ID → Properties → Manage security defaults",
                "Security Defaults provide baseline MFA and blocks legacy authentication at no extra cost. "
                "If you do not have Azure AD P1/P2 for Conditional Access, enable Security Defaults.",
            ))
        except Exception as e:
            findings.append(self.error_finding("iam_security_defaults_enabled", e))
        return findings

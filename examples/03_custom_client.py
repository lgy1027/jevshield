from jevshield import JevClient, guard, SecurityViolationError

# Configure dedicated client for private enterprise gateway
enterprise_client = JevClient(
    api_key="sk-enterprise-sample-key",
    base_url="https://gateway.internal.corp/v1/systemone",
    timeout=1.5
)

@guard(risk_threshold="medium_risk", interactive=False, client=enterprise_client)
def modify_user_role(user_id: int, new_role: str):
    """Elevates or changes permission groups for a target identity."""
    return f"User {user_id} set to {new_role}"

if __name__ == "__main__":
    try:
        # Evaluated via the enterprise client instance
        modify_user_role(1001, "superuser_admin")
    except SecurityViolationError as e:
        print(f"🛡️ Access Denied: {e}")

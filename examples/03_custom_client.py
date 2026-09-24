from jevshield import DevelopmentPolicy, JevClient, guard

# Configure a dedicated enterprise gateway client. An explicit empty key keeps
# this runnable example offline even if JEV_API_KEY is set in the shell; supply
# a real key with ProductionPolicy in an application deployment.
enterprise_client = JevClient(
    api_key="",
    base_url="https://gateway.internal.corp/v1/systemone",
    timeout=1.5
)

@guard(policy=DevelopmentPolicy(), client=enterprise_client)
def modify_user_role(user_id: int, new_role: str):
    """Elevates or changes permission groups for a target identity."""
    return f"User {user_id} set to {new_role}"

if __name__ == "__main__":
    print(modify_user_role(1001, "superuser_admin"))

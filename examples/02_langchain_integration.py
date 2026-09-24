from langchain_core.tools import tool
from jevshield import (
    DevelopmentPolicy,
    JevClient,
    SecurityViolationError,
    guard_langchain_tool,
)

# Keep this runnable demo local even if the shell exports a real JEV_API_KEY.
demo_client = JevClient(api_key="")

@tool
def delete_s3_bucket(bucket_name: str, force: bool = False):
    """Permanently deletes an Amazon S3 storage bucket and all its contents."""
    return f"Bucket {bucket_name} dropped."

@tool
def list_files(path: str):
    """Lists files within a specified local filesystem directory."""
    return f"Files at {path}: ['app.py', 'README.md']"

def build_guarded_tools():
    """Wrap the two LangChain tools with the current policy-first API."""

    policy = DevelopmentPolicy()
    return (
        guard_langchain_tool(delete_s3_bucket, policy=policy, client=demo_client),
        guard_langchain_tool(list_files, policy=policy, client=demo_client),
    )


if __name__ == "__main__":
    guarded_delete, guarded_list = build_guarded_tools()

    print("1. Running Safe Tool...")
    print(guarded_list.invoke({"path": "/home/user/repo"}))

    print("\n2. Running Guarded Destructive Tool...")
    try:
        guarded_delete.invoke({"bucket_name": "prod-customer-backups", "force": True})
    except SecurityViolationError as e:
        print(f"🛡️ Intercepted by JevShield: {e.reason}")

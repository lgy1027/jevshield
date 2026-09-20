from langchain_core.tools import tool
from jevshield import guard_langchain_tool, SecurityViolationError

@tool
def delete_s3_bucket(bucket_name: str, force: bool = False):
    """Permanently deletes an Amazon S3 storage bucket and all its contents."""
    return f"Bucket {bucket_name} dropped."

@tool
def list_files(path: str):
    """Lists files within a specified local filesystem directory."""
    return f"Files at {path}: ['app.py', 'README.md']"

if __name__ == "__main__":
    # Wrap LangChain tools with 1-line middleware
    guarded_delete = guard_langchain_tool(delete_s3_bucket, interactive=False)
    guarded_list = guard_langchain_tool(list_files, interactive=False)

    print("1. Running Safe Tool...")
    print(guarded_list.invoke({"path": "/home/user/repo"}))

    print("\n2. Running Guarded Destructive Tool...")
    try:
        guarded_delete.invoke({"bucket_name": "prod-customer-backups", "force": True})
    except SecurityViolationError as e:
        print(f"🛡️ Intercepted by JevShield: {e.reason}")

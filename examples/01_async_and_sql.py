import asyncio

from jevshield import DevelopmentPolicy, JevClient, SecurityViolationError, guard

# An empty explicit key selects JevShield's local mock evaluator even when a
# shell environment has a real JEV_API_KEY. Replace this with an application
# client when connecting the example to a live evaluator.
demo_client = JevClient(api_key="")

# 1. 异步 Shell 工具
@guard(policy=DevelopmentPolicy(), client=demo_client)
async def async_bash_executor(command: str):
    """Executes non-blocking terminal commands."""
    await asyncio.sleep(0.05)
    return f"Executed: {command}"

# 2. 数据库执行工具
@guard(policy=DevelopmentPolicy(), client=demo_client)
def execute_sql_query(query: str):
    """Executes database queries against the primary cluster."""
    return f"Query ok: {query}"

async def main():
    print("=== Testing Safe Database Query ===")
    res1 = execute_sql_query("SELECT email, created_at FROM users WHERE id = 42;")
    print(res1)

    print("\n=== Testing Destructive Database Query ===")
    try:
        execute_sql_query("DROP TABLE users;")
    except SecurityViolationError as err:
        print(f"🛡️ Caught expected violation: {err}")

    print("\n=== Testing Async Execution Gate ===")
    try:
        await async_bash_executor("rm -rf /var/lib/docker")
    except SecurityViolationError as err:
        print(f"🛡️ Caught async violation: {err}")

if __name__ == "__main__":
    asyncio.run(main())

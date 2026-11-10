#!/usr/bin/env python3
"""End-to-end acceptance checks. Requires a running privileged Linux service."""
import json
import os
import subprocess
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

BASE = os.environ.get("MINI_SANDBOX_URL", "http://127.0.0.1:3000")
CGROUP_BASE = "/sys/fs/cgroup/mini-sandbox"

def post(payload):
    body = json.dumps(payload).encode()
    request = urllib.request.Request(
        BASE + "/execute", data=body,
        headers={"content-type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(request, timeout=45) as res:
            return res.status, json.load(res)
    except urllib.error.HTTPError as e:
        return e.code, json.load(e)

def run(language, code, **kwargs):
    status, response = post({"language": language, "code": code, **kwargs})
    assert status == 200, (status, response)
    return response

def test():
    result = run("python", "print(1 + 1)")
    assert result["stdout"].strip() == "2" and result["exit_code"] == 0, result

    result = run("node", "console.log(2 + 2)")
    assert result["stdout"].strip() == "4" and result["exit_code"] == 0, result

    result = run("python",
        "import os;print(open('input.txt').read(), os.environ['VALUE'])",
        files=[{"path": "input.txt", "content": "aGk="}],
        env_vars=[["VALUE", "yes"]])
    assert result["stdout"].strip() == "hi yes", result

    result = run("python", "raise ValueError('expected')")
    assert result["exit_code"] != 0 and "ValueError" in result["stderr"], result

    result = run("python", "import time;time.sleep(3)", timeout_ms=150)
    assert result["timed_out"], result

    result = run("python", "print('a'*200000)")
    assert result["output_truncated"] and len(result["stdout"]) <= 128 * 1024, result

    result = run("python", "open('persist.txt','w').write('secret')")
    assert result["exit_code"] == 0, result
    result = run("python", "import os;print(os.path.exists('persist.txt'))")
    assert result["stdout"].strip() == "False", result

    result = run("python",
        "import socket\ntry:\n socket.create_connection(('1.1.1.1',80),0.5)\n print('OPEN')\nexcept OSError:\n print('BLOCKED')")
    assert result["stdout"].strip() == "BLOCKED", result

    result = run("python",
        "try:\n open('/workspace/big.bin','wb').write(b'x'* (70*1024*1024))\n print('OPEN')\nexcept OSError:\n print('QUOTA')")
    assert result["stdout"].strip() == "QUOTA", result

    result = run("python",
        "import subprocess;subprocess.Popen(['/bin/sleep','30']);print('spawned')")
    assert result["stdout"].strip() == "spawned", result

    status, response = post({"language":"python", "code":"print(1)",
                             "files":[{"path":"../escape", "content":""}]})
    assert status == 400, (status, response)

    with ThreadPoolExecutor(max_workers=2) as pool:
        slow = pool.submit(run, "python", "import time;time.sleep(1.5)",
                           timeout_ms=3000)
        time.sleep(0.3)
        status, response = post({"language":"python", "code":"print(1)"})
        assert status == 429, (status, response)
        slow.result()

    # OOM is expected to kill the sandbox and still leave no cgroup behind.
    status, response = post({
        "language":"python",
        "code":"x=bytearray(500*1024*1024);print(len(x))",
        "timeout_ms":7000
    })
    assert status == 200 and response["oom_killed"], (status, response)

    remaining = [x for x in os.listdir(CGROUP_BASE) if os.path.isdir(os.path.join(CGROUP_BASE,x))]
    assert not remaining, ("cgroup leaked after execution", remaining)
    print("PASS: Python, Node, files/env, exceptions, deadline, output, fs isolation, "
          "network, disk quota, background processes, validation, concurrency, OOM, cleanup")

if __name__ == "__main__":
    test()

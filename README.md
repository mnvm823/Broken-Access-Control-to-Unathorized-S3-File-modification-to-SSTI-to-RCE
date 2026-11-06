# Broken Access Control to S3 Template Modification to SSTI and RCE

> This report documents an authorized security test in a CTF environment. Do not test systems without permission. Sensitive values and command-execution details have been removed from this public report.

## Executive summary

The Northline Pages publishing platform had three connected security issues:

1. An authenticated user could change the `project_id` submitted when accepting an invitation and add their account to another workspace as an editor.
2. The upload-signing endpoint accepted a client-provided storage key without restricting it to an allowed path. This allowed an editor to overwrite the workspace's `render/layout.html` template in object storage.
3. The preview worker rendered that template with an unsandboxed Jinja2 environment. When a preview was generated, the worker evaluated attacker-controlled template expressions. In the authorized CTF test, this led to command execution in the worker container and access to sensitive worker data.

Together, these issues allowed an attacker who could create an account to gain access to another workspace, modify its template, and compromise the preview worker. The report below describes the evidence and impact. Secret values and command-execution payloads are intentionally redacted.

## Finding 1: Broken access control when accepting a project invitation

- **Target:** `northline.prod.local:9080`
- **Endpoint:** `POST /api/data/project_memberships`
- **Affected parameter:** `project_id`
- **Required access:** An authenticated account. Accounts could be created through the application.

### Description and impact

The invitation acceptance flow trusted the `project_id` and `role` values supplied by the client. By changing the project UUID in the membership request, I added my account to a different workspace with the `editor` role. I could then access workspace information, including members' names and email addresses.

### Evidence

I created an account named Bob and generated an invitation for that account. While accepting the invitation, I changed the project UUID in the intercepted membership request to the target workspace's UUID. The server returned `201 Created`, and the target workspace appeared in Bob's dashboard.

<img width="1901" height="948" alt="Invitation created for Bob" src="https://github.com/user-attachments/assets/916b4f2d-24ed-4059-ad20-d0057e658c3d" />

<img width="1892" height="886" alt="Invitation request intercepted" src="https://github.com/user-attachments/assets/246aea05-46f8-4b30-a1c5-8de4bb799bbf" />

<img width="1532" height="800" alt="Membership request accepted" src="https://github.com/user-attachments/assets/2a5d1f7a-42a0-4604-b708-77b59df7b373" />

<img width="1867" height="896" alt="Target workspace visible in dashboard" src="https://github.com/user-attachments/assets/b2d1bbba-a0bf-4a75-ad86-31473e8ef60e" />

<img width="1913" height="962" alt="Workspace member details" src="https://github.com/user-attachments/assets/21acd9a5-b904-4e15-8ef3-cdb1206a49e2" />

### Remediation

The server should look up the invitation using its token and derive the project, invited user, and role from that invitation record. It should verify that the invitation is valid, has not expired, and has not already been used. Do not accept client-supplied `project_id` or `role` as authority for creating a membership.

## Finding 2: Arbitrary storage key accepted by the upload-signing endpoint

- **Target:** `northline.prod.local:9080`
- **Endpoint:** `POST /api/projects/{project_id}/uploads/sign`
- **Affected parameter:** `key`
- **Required access:** Editor access to a project.

### Description and impact

The upload-signing endpoint accepted an arbitrary storage key from the request. An editor could request a pre-signed S3 `PUT` URL for the project's `render/layout.html` object and replace the template. The normal project upload flow should not allow users to overwrite this internal rendering template.

### Evidence

The Templates page showed that the application used Jinja rendering. I supplied the template object's storage key to the signing endpoint, received a pre-signed upload URL, and used it to replace the template. After generating a new preview, the modified content appeared in the result.

<img width="1568" height="750" alt="Templates page" src="https://github.com/user-attachments/assets/026c4f6d-3041-4a1c-a6cb-0d9838b14ac6" />

<img width="1517" height="777" alt="Upload-signing response" src="https://github.com/user-attachments/assets/b4ff160b-ef5e-4fad-84d0-ab18ff280b37" />

<img width="1888" height="983" alt="Modified template" src="https://github.com/user-attachments/assets/326f93f4-ed41-4db5-a190-a84b985a19ba" />

<img width="1918" height="1002" alt="Preview showing modified template" src="https://github.com/user-attachments/assets/0f2b32e7-d570-411c-9cee-6838a0dd346d" />

### Remediation

Do not use a client-supplied storage key as the destination for a signed upload. Generate the key on the server from the authenticated user's project and the specific upload type. Enforce an allowlist of permitted directories and file types, and ensure the signed URL can only write to that exact key. Keep internal rendering templates outside the user's upload area.

## Finding 3: Server-side template injection in the preview worker

- **Target:** `northline.prod.local:9080`
- **Affected component:** Jinja2 rendering in `/app/worker.py`
- **Trigger:** Generate a project preview after the template has been modified.
- **Required access:** Editor access to the project.

### Description and impact

The background preview worker rendered the stored template using Jinja2's default `Environment`. Because users who could modify the template could include Jinja expressions, the worker evaluated content controlled by the user. A harmless test expression, `{{ 7 * 7 }}`, was rendered as `49`, confirming that expressions in the template were evaluated.

In the authorized CTF test, the template issue also led to command execution in the worker container. This exposed worker environment data, source code, and credentials. The credential values, private key, and command-execution examples have been removed from this public report. Any real credentials exposed during testing should be rotated.

The relevant worker behavior was:

```python
from jinja2 import Environment

environment = Environment(autoescape=True)
html = environment.from_string(template).render(site=site)
```

Autoescaping helps protect rendered HTML from certain injection attacks, but it does not prevent server-side template injection or restrict what template expressions can access.

### Evidence

I replaced the template with one containing a harmless arithmetic expression and generated a preview. The result showed that the expression had been evaluated.

<img width="1845" height="953" alt="Preview showing evaluated template expression" src="https://github.com/user-attachments/assets/83960cc4-51b4-4ec0-a032-162b4e886a89" />

The authorized test also confirmed access to sensitive worker data and files. Those values are omitted here because they included credentials and private key material.

### Remediation

Do not render user-controlled templates with a general-purpose template environment. If Jinja2 is required, use `SandboxedEnvironment` as an additional restriction, keep the template context minimal, and test the exact allowed template features. A sandbox is not a substitute for access control or isolation. Where possible, use a logic-less template format instead.

Run the preview worker with minimal permissions and network access. Do not expose long-lived credentials through environment variables or mounted files unless required. Use short-lived, narrowly scoped credentials and rotate any credentials that may have been exposed.

## Overall impact

The three findings formed a chain. A user could join a workspace without authorization, overwrite its rendering template, and cause the preview worker to evaluate the modified template. In the CTF environment, this resulted in command execution in the worker container and access to sensitive worker data.

## CVSS assessment

The scores below are the original assessments from the test. The endpoints require an account, although accounts could be created through the application. Review the `PR` value for Findings 1 and 2 and for the overall chain to ensure it reflects the account requirement under the scoring assumptions used.

### Finding 1: Broken access control

**CVSS 3.1:** `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N` - **6.5 (Medium)**

The issue allowed access to another workspace and exposed member names and email addresses. The user had to create and authenticate an account, but self-registration was available.

### Finding 2: Arbitrary storage key in pre-signed uploads

**CVSS 3.1:** `AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N` - **4.3 (Medium)**

Exploitation required editor access and allowed modification of the project's rendering template.

### Finding 3: Server-side template injection leading to command execution

**CVSS 3.1:** `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` - **9.9 (Critical)**

The preview worker evaluated the modified template. In the CTF test, this resulted in command execution and access to data and credentials in the worker container.

### Overall vulnerability chain

**CVSS 3.1:** `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` - **10.0 (Critical)**

This score treats the initial access as requiring no privileges because an attacker could self-register. The chain still requires an account to use the affected endpoints, so the `PR` value should be reviewed against the intended scoring assumptions.

## Remediation summary

1. Derive invitation membership details from a valid server-side invitation record. Do not trust client-supplied project IDs or roles.
2. Generate upload keys on the server and allow uploads only to explicitly permitted project paths. Do not allow uploads to internal template objects.
3. Do not render user-controlled templates in an unsandboxed Jinja2 environment. Restrict template capabilities and context, or use a logic-less template system.
4. Isolate the preview worker, limit its network access, and minimize its permissions and secrets.
5. Treat a WAF as an additional detection layer only. It does not replace authorization checks, upload path restrictions, or safe template rendering.
6. Keep Jinja2 updated. Version updates do not make unsandboxed rendering of untrusted templates safe.

## References

- [OWASP Top 10: A01:2021 Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [PortSwigger Web Security Academy: Server-side template injection](https://portswigger.net/web-security/server-side-template-injection)
- [Jinja2 documentation: Sandboxed Environment](https://jinja.palletsprojects.com/en/3.1.x/sandbox/)
- [AWS S3 documentation: Uploading objects with presigned URLs](https://docs.aws.amazon.com/AmazonS3/latest/userguide/PresignedUrlUploadObject.html)

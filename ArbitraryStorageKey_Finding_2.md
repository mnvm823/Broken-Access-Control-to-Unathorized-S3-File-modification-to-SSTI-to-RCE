# Finding 2 — Arbitrary Storage Key in Pre-Signed Uploads

## Vulnerability Definition & Executive Summary

The Northline Pages upload-signing endpoint accepts a caller-supplied storage key without restricting it to the authorized project's asset directory. An editor can request a pre-signed S3-compatible PUT URL for an internal rendering template, such as `render/layout.html`, and overwrite that object.

This finding is the bridge between unauthorized workspace membership and server-side template injection. Finding 1 can provide an attacker with editor access to a target workspace. Replacing the rendering template then supplies attacker-controlled Jinja2 code to the preview worker, as described in [[Finding 3 - Writeup]].

- Target: **northline.prod.local:9080**
- Vulnerable endpoint **POST request** to **/api/projects/{project_id}/uploads/sign**
- Vulnerable parameter: POST parameter `key`
- Related findings: Finding 1 - Writeup (Broken Access Control) (access prerequisite); Finding 3 - Writeup (SSTI leading to RCE) (downstream impact)

## Technical Details

On **northline.prod.local:9080** the **POST request** to **/api/projects/{project_id}/uploads/sign** accepts an arbitrary storage `key` instead of limiting uploads to the caller's asset directory. A request for a key under **projects/<target-project-id>/render/** was signed successfully. The resulting pre-signed URL permitted a PUT to **render/layout.html**, outside the intended **projects/<authorized-project-id>/assets/** namespace. This finding is exploitable after obtaining editor access to the target workspace (for example, through Finding 1).

As a result, the attacker can leverage the generated pre-signed URL to upload and overwrite template files on the underlying object storage bucket **/nl-assets/**. This allows the attacker to replace trusted rendering layouts with malicious template payloads.

> *NOTE: The signed URL is time-limited and tied to the requested object key. The URLs captured during testing are expired and should not be reused; generate a new one during reproduction.*

## Proof of Concept

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

## Impact

An editor can modify a server-side rendering template stored in the project's object-storage namespace. By itself, this demonstrates an integrity impact. Combined with the unsafe template evaluation in Finding 3, the overwritten template becomes a route to command execution in the preview worker.

## CVSS

`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N` — **4.3 (Medium)**

- **AV:N:** The endpoint is reachable over the network.
- **AC:L:** Changing the requested key is sufficient to request a URL for the template object.
- **PR:L:** Editor access to the target project is required.
- **UI:N:** No action by another user is required; the attacker initiates the upload and preview.
- **S:U:** The provisional score treats the signing endpoint and object storage as part of the same application security authority.
- **C:N / I:L / A:N:** This finding alone demonstrated template modification, not direct disclosure or service disruption.

## Remediation

- Build object keys server-side from the authenticated project ID and a validated asset name.
- Restrict signed uploads to an explicit per-project asset prefix. Do not accept arbitrary object keys from clients.
- Reject attempts to target server-managed paths such as `render/`, even when the path contains no traversal sequence.
- Normalize and validate paths before signing; string checks for `../` alone are insufficient.
- Use storage credentials and bucket policies that cannot write server-managed templates from user-upload workflows.
- Bind the project ID in the route to the authenticated user's verified membership and permissions.

## Relationship to Other Findings

- **Prerequisite:** [[Finding 1 - Writeup]] describes how an attacker can obtain editor access to the target workspace.
- **Enables:** [[Finding 3 - Writeup]]. Overwriting `render/layout.html` supplies attacker-controlled template source to the preview worker.

## References

- [AWS: Uploading objects with presigned URLs](https://docs.aws.amazon.com/AmazonS3/latest/userguide/PresignedUrlUploadObject.html)
- [OWASP Top 10: A01 Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)

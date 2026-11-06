# Finding 1:  Broken Access Control in Invitation Acceptance

## Vulnerability Definition & Executive Summary

The Northline Pages invitation-redemption flow allows an authenticated user to create a membership in a workspace other than the one associated with the invitation. The endpoint trusts the client-supplied `project_id` and `role` rather than deriving those values from the invitation token stored by the server.

By creating an invitation for an account they control and changing the membership request during redemption, an attacker can add that account to a target workspace with editor privileges. The assessment confirmed that the account could view workspace member names and email addresses.

This is the entry point to the broader chain. Editor access enables the storage-key manipulation described in Finding 2, which in turn enables the template injection and command execution described in [[Finding 3 - Writeup]].

- Target: **northline.prod.local:9080**
- Vulnerable endpoint: **POST /api/data/project_memberships**
- Vulnerable parameters: POST parameter `project_id`

## Technical Details

On **northline.prod.local:9080** through **/api/data/project_memberships**, the HTTP requests containing a manipulated `project_id` and `role` parameter within the JSON payload were transmitted during invitation redemption, bypassing ownership validation checks between the issued invitation token and the target workspace.

As a result, the attacker can associate their authenticated user account with any customer project/workspace on the platform with elevated `editor` permissions, granting unauthorized read access to the workspace. 

The issue is not simply the ability to edit the request, rather the server must enforce the invitation's project and role on the server side. Client-side controls cannot establish that authorization relationship.

## Proof of Concept

_The test used a newly created account named Bob and an invitation intended for that account.
_

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


## Impact

An attacker can join a workspace without the owner's authorization and receive editor access. In the observed environment, this exposed workspace member names and email addresses. The editor membership also satisfies the access prerequisite for Finding 2, enabling the rest of the documented chain.

No availability impact was demonstrated for this finding.

## CVSS

`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N` — **5.4 (Medium, provisional)**

- **AV:N:** The endpoint is reachable over the network.
- **AC:L:** No unusual conditions were required beyond obtaining a target workspace ID.
- **PR:L:** The attacker needs an account; self-registration was available in the CTF.
- **UI:N:** No action by a target workspace user is required; the attacker redeems their own invitation.
- **S:U:** This provisional score treats the affected membership and workspace data as within the same application security authority. Reassess this metric if the platform's tenant boundaries represent separate security authorities.
- **C:L / I:L:** The test exposed limited member information and created an unauthorized editor membership.
- **A:N:** No availability impact was demonstrated.

## Remediation

- Do not accept `project_id` or `role` as authoritative values from the membership request.
- Resolve the invitation token on the server and verify that it is valid, unexpired, unused, and intended for the accepting account.
- Assign the project ID and role from the stored invitation record, not from request-body values.
- Create the membership atomically after validation and prevent duplicate or cross-project membership creation.
- Add authorization tests for invalid, expired, reused, and cross-workspace invitation tokens.

## Relationship to Other Findings

- **Enables:** Finding 2 - Writeup. The unauthorized editor membership provides the role required to request a signed upload URL for the target workspace.
- **Leads to:** Finding 3 - Writeup. By enabling Finding 2, it is the first step in the complete path to SSTI and worker-container command execution.

## References

- [OWASP Top 10: A01 Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)

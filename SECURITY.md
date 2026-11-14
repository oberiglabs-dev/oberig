# Security policy

Oberig sits between your agent and NEAR AI Cloud and decides whether an enclave can be trusted, so a security bug in it matters. Thank you for reporting one.

## How to report

Please do not open a public issue for a security problem.

Open a private security advisory on GitHub: on the repository's **Security** tab, choose **Report a vulnerability**. Only you and the maintainers can read it, and the fix can be prepared there before anything is public.

If you cannot use that form, open an issue that says only that you have a security report, with no details, and we will set up a private channel with you.

Please include:

- what an attacker can do, and what they need first
- steps to reproduce or a small proof of concept
- the output of `oberig --version`, your OS and Node.js version

Never send your NEAR AI key or other real secrets. Test values are enough.

## What counts

For example: Oberig sending a prompt when an attestation check should have failed, reporting a bad or mismatched answer signature as verified, letting a secret in a covered format reach NEAR AI unmasked, letting a web page in your browser reach the gateway past the Host and Origin checks, or the gateway writing keys or prompts to disk or sending them to a host the README does not list.

The limits the README already states (for example, Intel TCB status is not checked, and pattern matching can miss things) are known. Ideas to close them are welcome as ordinary issues.

## Supported versions

Fixes go into the latest release only, currently 0.1.x.

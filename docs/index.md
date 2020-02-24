---
layout: default
---

XOAUTH2 support based on auth-source-xoauth2.el.  To enable XOAUTH2,
add the following to .gnus.el

```elisp
(require 'gnus-xoauth2)
(gnus-xoauth2-enable)

(setq gnus-secondary-select-methods
  (nnimap "foo.gmail.com"
    (nnimap-authenticator xoauth2)
    (nnimap-user "foo@gmail.com")
    (nnimap-address "imap.gmail.com")
    (nnimap-server-port "imaps")
    (nnimap-stream ssl)))
```

And `pass edit foo.gmail.com` to store OAUTH2 information to
password-store.

```
<client-secret>
username: <client-id>
auth-url: <auth-url>
token-url: <token-url>
scope: <scope>
```

[example auth-url, token-url, and scope are in `ext-ouath2-*-progs`]

gnus-xoauth2.el reads

    client-id, client-secret, auth-url, token-url, and scope

from password-store. Then by using `oauth2.el', this fetches access
token with above parameters.

If you are using this to authenticate to Google, the values can be
obtained through the following procedure (note that Google changes
this procedure somewhat frequently, so the steps may be slightly
different):

1. Go to the developer console, https://console.developers.google.com/project
2. Create a new project (if necessary), and select it once created.
3. Select "APIs & Services" from the navigation menu.
4. Select "Credentials".
5. Create new credentials of type "OAuth Client ID".
6. Choose application type "Other".
7. Choose a name for the client.

This should get you all the values.

# Privacy Policy

This is software, which allows users to XOAUTH2 authentication for
IMAP and SMTP.

During setup, This software may try to contact external DNS servers,
and OAUTH2 servers to try and work the settings needed for your
account.  This software stores OAUTH2 authentication information
(OAUTH2 tokens) locally on your computer and does not transmit it
other than OAUTH2 servers.

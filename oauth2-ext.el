;;; oauth2-ext.el --- Extended oauth2.el             -*- lexical-binding: t; -*-

;; Copyright (C) 2020  OGAWA Hirofumi

;; Author: OGAWA Hirofumi <hirofumi@mail.parknet.co.jp>
;; Keywords: tools

;; This program is free software; you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.

;; This program is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU General Public License for more details.

;; You should have received a copy of the GNU General Public License
;; along with this program.  If not, see <https://www.gnu.org/licenses/>.

;;; Commentary:

;; Extending oauth2.el to support multi-account, plstore encrypt key,
;; error handling, mini-httpd for redirect-uri, random state and
;; verify, PKCE protocol, and password-store.

;;; Code:

(eval-when-compile (require 'cl-lib))
(eval-when-compile (require 'subr-x))
(require 'url)
(require 'plstore)
(require 'auth-source-pass)

(defgroup oauth2-ext nil
  "Extending oauth2.el"
  :version "28.1"
  :group 'oauth2-ext)

(defcustom oauth2-ext-token-file (concat user-emacs-directory "oauth2.plstore")
  "File path where store OAuth tokens."
  :type 'file)

(defun oauth2-ext-pass-gpg-id ()
  "Get gpg id from password-store's .gpg-id."
  (let ((gpg-id (concat auth-source-pass-filename "/.gpg-id")))
    (when (file-exists-p gpg-id)
      (with-temp-buffer
	(insert-file-contents-literally gpg-id)
	(car (split-string (buffer-string) "\n" t))))))

(defcustom oauth2-ext-encrypt-to (or (oauth2-ext-pass-gpg-id)
				     plstore-encrypt-to)
  "Recipient(s) used for encrypting secret entries.
May either be a string or a list of strings.  If it is nil,
symmetric encryption will be used."
  :type '(choice (const nil) (repeat :tag "Recipient(s)" string)))

(defcustom oauth2-ext-use-random-state t
  "If non-nil, add random state to authz request."
  :type 'boolean)

(defcustom oauth2-ext-use-pkce t
  "If non-nil, use PKCE protocol."
  :type 'boolean)

(defcustom oauth2-ext-pkce-verifier-length 64
  "Length of PKCE code verifier (must be >= 43)."
  :type 'boolean)

(defcustom oauth2-httpd-response-timeout 60
  "Seconds until timeout of authorization response."
  :type 'string)

(defcustom oauth2-httpd-response-title "OAuth2 response"
  "Title of authorization response used by `oauth2-httpd-auth-response-default'."
  :type 'string)

(defcustom oauth2-httpd-make-html #'oauth2-httpd-auth-response-default
  "Function to make html content to response to redirected authz code."
  :type 'function)

(defun oauth2-httpd-request-parse (string)
  "Parse http request in STRING."
  (let ((request (car (split-string string "\r\n"))))
    (split-string request " ")))

(defconst oauth2-httpd-code-alist
  '((200 . "OK")
    (404 . "Not Found")))

(defun oauth2-httpd-send-response (client content code)
  "Send http CODE response with CONTENT to CLIENT process."
  (let ((date (let ((system-time-locale "C"))
		(format-time-string "%a, %d %b %Y %T GMT" nil t)))
	(content-length (length content))
	(code-msg (alist-get code oauth2-httpd-code-alist))
	(code (number-to-string code)))
    (process-send-string
     client
     (concat "HTTP/1.1 " code " " code-msg "\r\n"
	     "Server: localhost\r\n"
	     "Connection: close\r\n"
	     "Date: " date "\r\n"
	     "Content-Type: text/html; charset=utf8\r\n"
	     (concat "Content-Length: " (number-to-string content-length) "\r\n")
	     "\r\n"
	     content))))

(defconst oauth2-httpd-html-template
  "
<!DOCTYPE html>
<html>
  <head>
    <meta charset=\"UTF-8\">
    <meta name=\"viewport\" content=\"width=device-width\">
    <title>oauth2-ext: OAuth2 Response</title>
    <meta name=\"description\" content=\"OAuth2 response page from oauth2-ext.el\">
    <style type=\"text/css\">
      .body {
	  padding: 0;
	  margin: 0;
      }
      .container {
	  display: flex;
	  flex-direction: column;
	  align-items: center;
      }
      .header {
	  min-height: 30px;
      }
      .footer {
	  min-height: 30px;
      }
      .main-box {
	  border-radius: 8px;
	  border:1px solid #dadce0;
	  margin:0 auto;
	  min-height:400px;
	  min-width:400px;
	  align-item: center;
      }
      .box {
	  border-bottom: 1px solid #ccc;
      }
      .text {
	  text-align: center;
	  padding: 5px 0;
      }
    </style>
  </head>
  <body class=\"body\">
    <div class=\"container\">
      <div class=\"header\"></div>
      <div class=\"main-box\">
	<div class=\"box\">
	  <div class=\"text\">%s</div>
	</div>
	<div>
	  <div class=\"text\">%s</div>
	</div>
      </div>
      <div class=\"footer\"></div>
    </div>
  </body>
</html>
")

(defun oauth2-httpd-auth-response-default (query-alist)
  "Make html content to response to CLIENT from QUERY-ALIST."
  (let ((msg (if (assoc "code" query-alist)
		 "success"
	       (or (nth 1 (assoc "error" query-alist)) "error"))))
    (format oauth2-httpd-html-template oauth2-httpd-response-title msg)))

(defun oauth2-httpd-auth-response (client query-alist)
  "Send response to CLIENT process from QUERY-ALIST."
  (let ((content (funcall oauth2-httpd-make-html query-alist)))
    (oauth2-httpd-send-response client content 200)))

(defun oauth2-httpd-send-404 (client)
  "Send http 404 error to CLIENT process."
  (oauth2-httpd-send-response client "" 404))

(defvar oauth2-httpd-callback-path "/oauth2-callback")

(defun oauth2-httpd-start ()
  "Start mini-httpd to serve redirect-uri request."
  (let* ((filter (lambda (proc string)
		   (let* ((serv-proc (process-get proc :serv-proc))
			  (request (oauth2-httpd-request-parse string))
			  (req-method (nth 0 request))
			  (req-path (nth 1 request))
			  (_req-ver (nth 2 request))
			  (url (url-generic-parse-url req-path))
			  (path-and-query (url-path-and-query url))
			  (path (car path-and-query))
			  (query (cdr path-and-query))
			  (query-alist (and query
					    (url-parse-query-string query))))
		     (if (or (null request) (null req-method) (null req-path)
			     (not (string= req-method "GET"))
			     (not (string= oauth2-httpd-callback-path path)))
			 (oauth2-httpd-send-404 proc)
		       (oauth2-httpd-auth-response proc query-alist)
		       (process-put serv-proc :response query-alist))
		     (delete-process proc))))
	 (serv-proc (make-network-process
		     :name "oauth2-redirect-httpd"
		     :service 0
		     :server t
		     :host 'local
		     :coding 'binary
		     :filter filter
		     :noquery t)))
    (process-put serv-proc :serv-proc serv-proc)
    serv-proc))

(defun oauth2-httpd-wait-response (serv-proc)
  "Wait mini-httpd response from SERV-PROC."
  (with-timeout (oauth2-httpd-response-timeout)
    (while (null (process-get serv-proc :response))
      (accept-process-output nil 1)))
  (let ((response (process-get serv-proc :response)))
    (delete-process serv-proc)
    response))

(defun oauth2-ext-compute-id (client-id auth-url token-url scope &optional keys)
  "Compute an unique id based on URLs.
The unique id is made from CLIENT-ID, AUTH-URL, TOKEN-URL,
SCOPE, and KEYS.  KEYS are arbitrary string or list of
string.  This allows to store the token in an unique way."
  (let ((keys (if (listp keys) keys (list keys))))
    (secure-hash 'md5 (apply #'concat client-id auth-url token-url scope
			     keys))))

(defun oauth2-ext-build-url (prefix query)
  "Build URL from PREFIX and QUERY.
QUERY is passed to `url-build-query-string'."
  (concat prefix
	  (if (string-match-p "\\?" prefix) "&" "?")
	  (url-build-query-string query)))

(defalias 'oauth2-json-read
  (if (fboundp 'json-parse-buffer)
      (lambda ()
	(json-parse-buffer :object-type 'alist
                           :null-object nil
                           :false-object :json-false))
    (require 'json)
    (defvar json-object-type)
    (declare-function json-read "json" ())
    (lambda ()
      (let ((json-object-type 'alist))
        (json-read))))
  "Read JSON object in buffer, move point to end of buffer.")

(defun oauth2-ext-request-access-parse ()
  "Parse the result of an OAuth request."
  (goto-char (point-min))
  (when (search-forward-regexp "^$" nil t)
    (oauth2-json-read)))

(defun oauth2-ext-make-access-request (url data)
  "Make an access request to URL using DATA in POST."
  (let ((url-request-method "POST")
        (url-request-data data)
        (url-request-extra-headers
	 '(("Content-Type" . "application/x-www-form-urlencoded"))))
    (with-current-buffer (url-retrieve-synchronously url)
      (let ((data (oauth2-ext-request-access-parse)))
        (kill-buffer (current-buffer))
        data))))

(defconst oauth2-ext-redirect-uri-manual "urn:ietf:wg:oauth:2.0:oob"
  "Redirect URI for Manual copy/paste.")

(defconst oauth2-ext-redirect-uri-programmatic "urn:ietf:wg:oauth:2.0:oob:auto"
  "Redirect URI for Programmatic extraction.")

(defun oauth2-ext-request-authorization (auth-url client-id
						  &optional scope state
						  redirect-uri extra)
  "Request OAuth authorization code at AUTH-URL by launching `browse-url'.

CLIENT-ID is the client id provided by the provider.
SCOPE is the list of resource scopes.
STATE is an arbitrary string to keep some object for CRLF attack.
REDIRECT-URI is uri how to get response from browser.  If
REDIRECT-URI is nil, `oauth2-ext-redirect-uri-manual' is used.
EXTRA is a list of extra query parameters that is passed to
`url-build-query-string'."
  (let ((query `((client_id ,client-id)
		 (response_type "code")
		 (redirect_uri ,(or redirect-uri
				    oauth2-ext-redirect-uri-manual))
		 ,@(and scope `((scope ,scope)))
		 ,@(and state `((state ,state)))
		 ,@extra)))
    (browse-url (oauth2-ext-build-url auth-url query))))

(defun oauth2-ext-request-access (token-url client-id client-secret code
					    &optional redirect-uri extra)
  "Request OAuth2 access token at TOKEN-URL.

CLIENT-ID is the client id provided by the provider.
CLIENT-SECRET is the client secret provided by the provider.
CODE should be obtained with `oauth2-request-authorization'.
REDIRECT-URI is uri how to get response from browser.  If
REDIRECT-URI is nil, `oauth2-ext-redirect-uri-manual' is used.
EXTRA is a list of extra query parameters that is passed to
`url-build-query-string'."
  (let ((query `((client_id ,client-id)
		 (client_secret ,client-secret)
		 (code ,code)
		 (redirect_uri ,(or redirect-uri
				    oauth2-ext-redirect-uri-manual))
		 (grant_type "authorization_code")
		 ,@extra)))
    (oauth2-ext-make-access-request token-url (url-build-query-string query))))

(defun oauth2-ext-request-refresh (token-url client-id client-secret
					     refresh-token
					     &optional extra)
  "Request OAuth2 refreshed access token at TOKEN-URL.

CLIENT-ID is the client id provided by the provider.
CLIENT-SECRET is the client secret provided by the provider.
REFRESH-TOKEN should be obtained with `oauth2-ext-request-access'
or previous `oauth2-ext-request-refresh'.
EXTRA is a list of extra query parameters that is passed to
`url-build-query-string'."
  (let ((query `((client_id ,client-id)
		 (client_secret ,client-secret)
		 (refresh_token ,refresh-token)
		 (grant_type "refresh_token")
		 ,@extra)))
    (oauth2-ext-make-access-request token-url (url-build-query-string query))))

(defun oauth2-ext-request-revoke (revoke-url token &optional token-type extra)
  "Request OAuth2 revoke token at REVOKE-URL.

TOKEN is the access-token or refresh-token.
TOKEN-TYPE is the access_token or refresh_token.
EXTRA is a list of extra query parameters that is passed to
`url-build-query-string'."
  (let ((query `((token ,token)
		 ,@(and token-type `((token_type_hint ,token-type)))
		 ,@extra)))
    (oauth2-ext-make-access-request revoke-url (url-build-query-string query))))

(defun oauth2-ext-make-random-state ()
  "Make random state string for authz request."
  (if (and (fboundp 'gnutls-available-p) (memq 'gnutls3 (gnutls-available-p)))
      (secure-hash 'sha256 'iv-auto 64)
    (secure-hash 'sha256 (let (vec)
			   (concat (dotimes (_i 64 vec)
				     (push (random 256) vec)))))))

(defun oauth2-ext-pkce-make-verifier (length)
  "Make PKCE code verifier string for LENGTH."
  (random t)
  (let ((limit (+ (- ?~ ?-) 1))
	vec)
    (while (< (length vec) length)
      (let ((c (+ (random limit) ?-)))
	(when (or (and (<= ?0 c) (<= c ?9))
		  (and (<= ?A c) (<= c ?Z))
		  (and (<= ?a c) (<= c ?z))
		  (= c ?-) (= c ?.) (= c ?_) (= c ?~))
	  (push c vec))))
    (concat vec)))

;; FIXME: support plain
(defvar oauth2-ext-pkce-challenge-method "S256")

(defun oauth2-ext-pkce-make-challenge (verifier)
  "Make PKCE code challenge from VERIFIER."
  (base64url-encode-string
   (secure-hash 'sha256 verifier nil nil t) t))

(defun oauth2-ext-pkce-params ()
  "Make PKCE query parameters."
  (let* ((verifier (oauth2-ext-pkce-make-verifier
		    oauth2-ext-pkce-verifier-length))
	 (challenge (oauth2-ext-pkce-make-challenge verifier)))
    `(((code_verifier ,verifier))
      ((code_challenge ,challenge)
       (code_challenge_method ,oauth2-ext-pkce-challenge-method)))))

(cl-defstruct (oauth2-ext-session
	       (:constructor nil)	; no default
	       (:copier nil)
	       (:predicate nil)
	       (:constructor oauth2-ext-session-make
			     (client-id
			      client-secret
			      auth-url
			      token-url
			      scope
			      &optional keys
			      &aux (plstore-id
				    (oauth2-ext-compute-id
				     client-id auth-url token-url scope
				     keys)))))
  "Make session structure for OAuth2.

Parameters for `oauth2-ext-session-make':
CLIENT-ID is the client id provided by the provider.
CLIENT-SECRET is the client secret provided by the provider.
AUTH-URL is URL to request authorization code.
TOKEN-URL is URL to request access token.
SCOPE is the list of resource scopes.
KEYS are arbitrary string or list of string.  This allows to
store the token in an unique way.

`oauth2-ext-session-redirect-uri' is uri how to get response from
browser.  If redirect-uri is nil, use localhost with internal
micro httpd.
`oauth2-ext-session-login-hint' is to add \"login_hint\"
parameter to authorization."

  plstore-id
  plstore
  (client-id nil :read-only t)
  (client-secret nil :read-only t)
  (auth-url nil :read-only t)
  (token-url nil :read-only t)
  (scope nil :read-only t)
  redirect-uri
  login-hint)

(defun oauth2-ext-session-plstore-open (session)
  "Open plstore for SESSION."
  (let ((plstore-encrypt-to oauth2-ext-encrypt-to))
    (or (oauth2-ext-session-plstore session)
	(setf (oauth2-ext-session-plstore session)
	      (plstore-open oauth2-ext-token-file)))))

(defun oauth2-ext-session-plist (session)
  "Return plist of plstore for SESSION."
  (let* ((plstore (oauth2-ext-session-plstore-open session))
         (id (oauth2-ext-session-plstore-id session)))
    (cdr (plstore-get plstore id))))

(defun oauth2-ext-session-update-plstore (session access-token refresh-token
						  access-response)
  "Update and plstore data for SESSION.
Updating entries are specified by ACCESS-TOKEN, REFRESH-TOKEN,
ACCESS-RESPONSE."
  (let* ((make-backup-files nil)
	 (plstore-encrypt-to oauth2-ext-encrypt-to)
	 (plstore (oauth2-ext-session-plstore-open session))
	 (plist (oauth2-ext-session-plist session))
         (id (oauth2-ext-session-plstore-id session))
	 (access-token (or access-token (plist-get plist :access-token)))
	 (refresh-token (or refresh-token (plist-get plist :refresh-token)))
	 (access-response (or access-response
			      (plist-get plist :access-response))))
    (plstore-put plstore id nil `(:access-token ,access-token
				  :refresh-token ,refresh-token
				  :access-response ,access-response))
    (plstore-save plstore)))

(defvar oauth2-ext-auth-prompt "Enter the code your browser displayed: ")

(defun oauth2-ext-auth-code (session &optional state extra)
  "Authenticate application via OAuth2.

SESSION is session structure made by `oauth2-ext-session-make'.
STATE is an arbitrary string to keep some object for CRLF
attack.  If STATE is nil and `oauth2-ext-use-random-state' is
non-nil, use random state value.
EXTRA is a list of extra query parameters that is passed to
`url-build-query-string'."
  (let ((auth-url (oauth2-ext-session-auth-url session))
	(client-id (oauth2-ext-session-client-id session))
	(scope (oauth2-ext-session-scope session))
	(state (or state (and oauth2-ext-use-random-state
			      (oauth2-ext-make-random-state))))
	(redirect-uri (oauth2-ext-session-redirect-uri session))
	serv-proc)

    (when (null redirect-uri)
      ;; start micro httpd
      (setq serv-proc (oauth2-httpd-start))
      (setq redirect-uri (format "http://localhost:%d%s"
				 (process-contact serv-proc :service)
				 oauth2-httpd-callback-path))
      (setf (oauth2-ext-session-redirect-uri session) redirect-uri))

    (oauth2-ext-request-authorization auth-url client-id scope state
				      redirect-uri extra)

    (cond
     (serv-proc
      ;; get response from micro httpd
      (let* ((response (oauth2-httpd-wait-response serv-proc))
	     (res-state (nth 1 (assoc "state" response))))
	(when (null response)
	  (error "OAuth2 failed to get authz response"))
	(when (and state (or (null res-state)
			     (not (string= state res-state))))
	  (error "OAuth2 failed verify of authz response state"))
	(when-let ((errcode (assoc "error" response)))
	  (error "OAuth2 authz response error: %s" errcode))
	(nth 1 (assoc "code" response))))
     (t
      (read-string oauth2-ext-auth-prompt)))))

(defun oauth2-ext-auth (session &optional state)
  "Authenticate application, then request access token via OAuth2.

SESSION is session structure made by `oauth2-ext-session-make'.
STATE is an arbitrary string to keep some object for CRLF attack."
  (let* ((pkce-params (and oauth2-ext-use-pkce (oauth2-ext-pkce-params)))
	 (login-hint (let ((hint (oauth2-ext-session-login-hint session)))
		       (and hint `((login_hint ,hint)))))
	 (extra (append (nth 1 pkce-params)
			login-hint))
	 (auth-code (oauth2-ext-auth-code session state extra)))
    (let ((token-url (oauth2-ext-session-token-url session))
	  (client-id (oauth2-ext-session-client-id session))
	  (client-secret (oauth2-ext-session-client-secret session))
	  (redirect-uri (oauth2-ext-session-redirect-uri session)))
      (oauth2-ext-request-access token-url client-id client-secret auth-code
				 redirect-uri (nth 0 pkce-params)))))

(defun oauth2-ext-auth-and-store (session)
  "Request access/refresh token and store it by using `plstore'.
If there is stored token, read it instead of requesting.

SESSION is session structure made by `oauth2-ext-session-make'.
Return nil if succeed, otherwise error response."
  (let ((response (oauth2-ext-auth session)))
    (if (assoc 'error response)
	response
      (let ((access-token (cdr (assoc 'access_token response)))
	    (refresh-token (cdr (assoc 'refresh_token response))))
	(oauth2-ext-session-update-plstore session access-token refresh-token
					   response)
	nil))))

(defun oauth2-ext-refresh (session)
  "Refresh OAUTH2 access token.

SESSION is session structure made by `oauth2-ext-session-make'.
Return nil if succeed, otherwise error response."
  (let* ((token-url (oauth2-ext-session-token-url session))
	 (client-id (oauth2-ext-session-client-id session))
	 (client-secret (oauth2-ext-session-client-secret session))
	 (plist (oauth2-ext-session-plist session))
	 (refresh-token (plist-get plist :refresh-token))
	 (response (oauth2-ext-request-refresh token-url client-id client-secret
					       refresh-token)))
    (if (assoc 'error response)
	response
      ;; Success
      (let ((access-token (cdr (assoc 'access_token response))))
	(oauth2-ext-session-update-plstore session access-token nil nil)
	nil))))

(defun oauth2-ext-auth-or-refresh (session)
  "Make new token or read stored token, then refresh.

SESSION is session structure made by `oauth2-ext-session-make'.
Return nil if succeed, otherwise error response."
  (let* ((plist (oauth2-ext-session-plist session))
	 (refresh-token (plist-get plist :refresh-token)))
    (when (or (null refresh-token) (oauth2-ext-refresh session))
      ;; If no refresh-token or refresh was failed, start from auth.
      (oauth2-ext-auth-and-store session))))

;;;###autoload
(defun oauth2-ext-access-token (session)
  "Get access token for OAUTH2.

SESSION is session structure made by `oauth2-ext-session-make'."
  (let ((response (oauth2-ext-auth-or-refresh session)))
    (if (assoc 'error response)
	(error "OAuth2 failed to get access token: %s" response)
      (let ((plist (oauth2-ext-session-plist session)))
	(plist-get plist :access-token)))))

(defconst oauth2-ext-gmail-props
  ;; Get from
  ;; https://accounts.google.com/.well-known/openid-configuration and
  ;; https://developers.google.com/identity/protocols/googlescopes
  '(:auth-url "https://accounts.google.com/o/oauth2/v2/auth"
	      :token-url "https://oauth2.googleapis.com/token"
	      :scope "https://mail.google.com/"))
(defconst oauth2-ext-mail-ru-props
  '(:auth-url "https://o2.mail.ru/login"
	      :token-url "https://o2.mail.ru/token"
	      :scope "mail.imap"))
(defconst oauth2-ext-yandex-imap-props
  '(:auth-url "https://oauth.yandex.com/authorize"
	      :token-url "https://oauth.yandex.com/token"
	      :scope "mail:imap_full"))
(defconst oauth2-ext-yandex-smtp-props
  '(:auth-url "https://oauth.yandex.com/authorize"
	      :token-url "https://oauth.yandex.com/token"
	      :scope "mail:smtp"))
(defconst oauth2-ext-yahoo-com-props
  '(:auth-url "https://api.login.yahoo.com/oauth2/request_auth"
	      :token-url "https://api.login.yahoo.com/oauth2/get_token"
	      :scope "mail-w"))
(defconst oauth2-ext-aol-props
  '(:auth-url "https://api.login.aol.com/oauth2/request_auth"
	      :token-url "https://api.login.aol.com/oauth2/get_token"
	      :scope "mail-w"))

(defcustom oauth2-ext-issuers-alist
  `(("imap.googlemail.com" . ,oauth2-ext-gmail-props)
    ("smtp.googlemail.com" . ,oauth2-ext-gmail-props)
    ("imap.gmail.com" . ,oauth2-ext-gmail-props)
    ("smtp.gmail.com" . ,oauth2-ext-gmail-props)

    ("imap.mail.ru" . ,oauth2-ext-mail-ru-props)
    ("smtp.mail.ru" . ,oauth2-ext-mail-ru-props)

    ("imap.yandex.com" . ,oauth2-ext-yandex-imap-props)
    ("smtp.yandex.com" . ,oauth2-ext-yandex-smtp-props)

    ("imap.mail.yahoo.com" . ,oauth2-ext-yahoo-com-props)
    ("smtp.mail.yahoo.com" . ,oauth2-ext-yahoo-com-props)

    ("imap.aol.com" . ,oauth2-ext-aol-props)
    ("smtp.aol.com" . ,oauth2-ext-aol-props))
  "The alist of endpoint URLs for OAUTH2."
  :type '(alist :key-type string :value-type list))

(provide 'oauth2-ext)
;;; oauth2-ext.el ends here

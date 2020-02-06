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
;; error handling, mini-httpd for redirect-uri, and password-store.

;;; Code:

(eval-when-compile (require 'subr-x))
(require 'url-parse)
(require 'url-util)
(require 'oauth2)
(require 'plstore)
(require 'auth-source-pass)

(defgroup oauth2-ext nil
  "Extending oauth2.el"
  :version "28.1"
  :group 'comm)

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
  (let ((title "OAuth2 response")
	(msg (if (assoc "code" query-alist)
		 "success"
	       (or (nth 1 (assoc "error" query-alist)) "error"))))
    (format oauth2-httpd-html-template title msg)))

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
  (catch 'got
    (dotimes (_i (* 60 30))
      (accept-process-output nil 1)
      (when (process-get serv-proc :response)
	(throw 'got nil))))
  (let ((response (process-get serv-proc :response)))
    (delete-process serv-proc)
    response))

(defconst oauth2-ext-redirect-uri-manual "urn:ietf:wg:oauth:2.0:oob"
  "Redirect URI for Manual copy/paste.")

(defconst oauth2-ext-redirect-uri-programmatic "urn:ietf:wg:oauth:2.0:oob:auto"
  "Redirect URI for Programmatic extraction.")

(defun oauth2-ext-request-authorization (auth-url client-id
						  &optional scope state redirect-uri)
  "Request OAuth authorization at AUTH-URL by launching `browse-url'.
CLIENT-ID is the client id provided by the provider.
SCOPE is the list of resource scopes.
REDIRECT-URI is uri how to get response from browser. If
REDIRECT-URI is nil, `oauth2-ext-redirect-uri-manual' is used."
  (browse-url (concat auth-url
		      (if (string-match-p "\?" auth-url) "&" "?")
		      "client_id=" (url-hexify-string client-id)
		      "&response_type=code"
		      "&redirect_uri=" (url-hexify-string redirect-uri)
		      (and scope
			   (concat "&scope=" (url-hexify-string scope)))
		      (and state
			   (concat "&state=" (url-hexify-string state))))))

(defun oauth2-ext-compute-id (auth-url token-url resource-url
				       &rest keys)
  "Compute an unique id based on URLs.
The unique id is made from AUTH-URL, TOKEN-URL, RESOURCE-URL, and KEYS.
This allows to store the token in an unique way."
  (secure-hash 'md5 (apply #'concat auth-url token-url resource-url keys)))

(defvar oauth2-ext-auth-prompt "Enter the code your browser displayed: ")

;;;###autoload
(defun oauth2-ext-auth (auth-url token-url client-id client-secret
				 &optional scope state redirect-uri)
  "Authenticate application via OAuth2."
  (let* ((serv-proc (or redirect-uri (oauth2-httpd-start)))
	 (redirect-uri (or redirect-uri
			   (format "http://localhost:%d%s"
				   (process-contact serv-proc :service)
				   oauth2-httpd-callback-path)))
	 (auth-code (progn
		      (oauth2-ext-request-authorization auth-url client-id
							scope state
							redirect-uri)
		      (cond
		       (serv-proc
			(let ((response (oauth2-httpd-wait-response serv-proc)))
			  (nth 1 (assoc "code" response))))
		       (t
			(read-string oauth2-ext-auth-prompt))))))
    (oauth2-request-access
     token-url
     client-id
     client-secret
     auth-code
     redirect-uri)))

(defun oauth2-ext-auth-and-store (auth-url token-url resource-url
					   client-id client-secret
					   &optional redirect-uri
					   &rest keys)
  "Request access to a resource and store it using `plstore'.

AUTH-URL, TOKEN-URL, RESOURCE-URL, CLIENT-ID, CLIENT-SECRET,
REDIRECT-URI are used for OAUTH2 protocol.  Stored token are
identified by AUTH-URL, TOKEN-URL, RESOURCE-URL, and KEYS."
  ;; We store a MD5 sum of all URL and keys
  (let* ((make-backup-files nil)
	 (plstore-encrypt-to oauth2-ext-encrypt-to)
	 (plstore (plstore-open oauth2-token-file))
         (id (apply #'oauth2-ext-compute-id
		    auth-url token-url resource-url keys))
         (plist (cdr (plstore-get plstore id))))
    ;; Check if we found something matching this access
    (if plist
        ;; We did, return the token object
        (make-oauth2-token :plstore plstore
                           :plstore-id id
                           :client-id client-id
                           :client-secret client-secret
                           :access-token (plist-get plist :access-token)
                           :refresh-token (plist-get plist :refresh-token)
                           :token-url token-url
                           :access-response (plist-get plist :access-response))
      (let ((token (oauth2-ext-auth auth-url token-url
                                    client-id client-secret resource-url
				    nil redirect-uri)))
        ;; Set the plstore
        (setf (oauth2-token-plstore token) plstore)
        (setf (oauth2-token-plstore-id token) id)
        (plstore-put plstore id nil `(:access-token
                                      ,(oauth2-token-access-token token)
                                      :refresh-token
                                      ,(oauth2-token-refresh-token token)
                                      :access-response
                                      ,(oauth2-token-access-response token)))
        (plstore-save plstore)
        token))))

(defun oauth2-ext-refresh-access (token auth-url resource-url redirect-uri)
  "Refresh OAUTH2 access TOKEN.
If refresh returned error, restart from `oauth2-ext-auth' with
AUTH-URL, RESOURCE-URL, and REDIRECT-URI parameters.  TOKEN
should be obtained with `oauth2-request-access'."
  (let* ((make-backup-files nil)
	 (plstore-encrypt-to oauth2-ext-encrypt-to)
	 (token-url (oauth2-token-token-url token))
	 (client-id (oauth2-token-client-id token))
	 (client-secret (oauth2-token-client-secret token))
	 (response (oauth2-make-access-request
                    token-url
                    (concat "client_id=" client-id
                            "&client_secret=" client-secret
                            "&refresh_token=" (oauth2-token-refresh-token token)
                            "&grant_type=refresh_token"))))
    (if (not (assoc 'error response))
	(setf (oauth2-token-access-token token)
	      (cdr (assoc 'access_token response)))
      ;; if refresh was error, restart from `oauth2-ext-auth'
      ;; FIXME: should check detail of error
      (let ((auth-token (oauth2-ext-auth auth-url token-url
					 client-id client-secret resource-url
					 nil redirect-uri)))
	(setf (oauth2-token-access-token token)
	      (oauth2-token-access-token auth-token))
	(setf (oauth2-token-refresh-token token)
	      (oauth2-token-refresh-token auth-token))
	(setf (oauth2-token-access-response token)
	      (oauth2-token-access-response auth-token))))
    ;; If the token has a plstore, update it
    (let ((plstore (oauth2-token-plstore token)))
      (when plstore
	(plstore-put plstore (oauth2-token-plstore-id token)
                     nil `(:access-token
                           ,(oauth2-token-access-token token)
                           :refresh-token
                           ,(oauth2-token-refresh-token token)
                           :access-response
                           ,(oauth2-token-access-response token)
                           ))
	(plstore-save plstore)))
    token))

(defun oauth2-ext-auth-or-refresh (auth-url token-url resource-url client-id
					    client-secret
					    &optional redirect-uri
					    &rest keys)
  "Make new token or read stored token, then refresh.

AUTH-URL, TOKEN-URL, RESOURCE-URL, CLIENT-ID, CLIENT-SECRET,
REDIRECT-URI are used for OAUTH2 protocol.  Stored token are
identified by AUTH-URL, TOKEN-URL, RESOURCE-URL, and KEYS."
  (let ((token (apply #'oauth2-ext-auth-and-store
		      auth-url token-url resource-url client-id client-secret
		      redirect-uri keys)))
    (oauth2-ext-refresh-access token auth-url resource-url redirect-uri)
    token))

;;;###autoload
(defun oauth2-ext-access-token (auth-url token-url resource-url
					 client-id client-secret
					 &optional redirect-uri
					 &rest keys)
  "Get access token for OAUTH2.

AUTH-URL, TOKEN-URL, RESOURCE-URL, CLIENT-ID, CLIENT-SECRET,
REDIRECT-URI are used for OAUTH2 protocol.  Stored token are
identified by AUTH-URL, TOKEN-URL, RESOURCE-URL, and KEYS."
  (let ((token (apply #'oauth2-ext-auth-or-refresh
		      auth-url token-url resource-url client-id client-secret
		      redirect-uri keys)))
    (oauth2-token-access-token token)))

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

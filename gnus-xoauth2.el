;;; gnus-xoauth2.el --- XOAUTH2 for gnus        -*- lexical-binding: t; -*-

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

;; XOAUTH2 support based on auth-source-xoauth2.el.  To enable
;; XOAUTH2, add the following to .gnus.el
;;
;;   (require 'gnus-xoauth2)
;;   (gnus-xoauth2-enable)
;;
;;   (setq gnus-secondary-select-methods
;;   (nnimap "foo.gmail.com"
;;      (nnimap-authenticator xoauth2)
;;      (nnimap-user "foo")
;;      (nnimap-address "imap.gmail.com")
;;      (nnimap-server-port "imaps")
;;      (nnimap-stream ssl))
;;
;; And "pass edit foo.gmail.com.gpg" to store OAUTH2 information to
;; password-store.
;;
;;   <client-secret>
;;   username: <client-id>
;;   auth-url: <auth-url>
;;   token-url: <token-url>
;;   scope: <scope>
;;
;; [example auth-url, token-url, and scope are in `ext-ouath2-*-progs`]
;;
;; gnus-xoauth2.el reads
;;
;;     client-id, client-secret, auth-url, token-url, and scope
;;
;; from password-store. Then by using `oauth2', this fetches access
;; token with above parameters.
;; 
;; If you are using this to authenticate to Google, the values can be
;; obtained through the following procedure (note that Google changes
;; this procedure somewhat frequently, so the steps may be slightly
;; different):
;; 
;; 1. Go to the developer console, https://console.developers.google.com/project
;; 2. Create a new project (if necessary), and select it once created.
;; 3. Select "APIs & Services" from the navigation menu.
;; 4. Select "Credentials".
;; 5. Create new credentials of type "OAuth Client ID".
;; 6. Choose application type "Other".
;; 7. Choose a name for the client.
;; 
;; This should get you all the values.

;;; Code:

(require 'cl-lib)
(require 'auth-source-pass)
(require 'oauth2)

(defgroup gnus-xoauth2 nil
  "XOAUTH2 support for gnus"
  :version "28.1"
  :group 'files)

;; Helpers for oauth2.el to support per-account plstore

(defcustom ext-oauth2-plstore-dir (concat user-emacs-directory "oauth2")
  "Directory to store encrypted OAUTH2 credential."
  :type 'string)

(defun ext-oauth2-pass-gpg-id ()
  "Get gpg id from password-store's .gpg-id."
  (let ((gpg-id (concat auth-source-pass-filename "/.gpg-id")))
    (when (file-exists-p gpg-id)
      (with-temp-buffer
	(insert-file-contents-literally gpg-id)
	(car (split-string (buffer-string) "\n" t))))))

(defcustom ext-oauth2-encrypt-to (or (ext-oauth2-pass-gpg-id)
				     plstore-encrypt-to)
  "Recipient(s) used for encrypting secret entries."
  :type 'file)

(defun ext-oauth2-plstore-file (host user)
  "Path of plstore file for HOST and USER."
  ;; Key is both of plstore's key (auth-url+token-url+scope) and
  ;; filename (i.e. if <user> is non-nil, <user>.plstore).  So the key
  ;; should be enough unique usually for usage.
  (cond
   (user
    (concat ext-oauth2-plstore-dir (format "/%s.plstore" user)))
   (host
    (concat ext-oauth2-plstore-dir (format "/%s.plstore" host)))
   (t
    oauth2-token-file)))

(defun ext-oauth2-refresh-access (token auth-url resource-url redirect-uri)
  "Refresh OAuth access TOKEN.
TOKEN should be obtained with `oauth2-request-access'."
  (let* ((token-url (oauth2-token-token-url token))
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
      ;; if refresh was error, restart from auth
      ;; FIXME: should check detail of error
      (let ((auth-token (oauth2-auth auth-url token-url
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

(defun ext-oauth2-auth-and-refresh (host user auth-url token-url resource-url
					 client-id client-secret
					 &optional redirect-uri)
  "Setup environment for HOST, then get and refresh access-token."
  (let* ((make-backup-files nil)
	 (oauth2-token-file (ext-oauth2-plstore-file host user))
	 (plstore-encrypt-to ext-oauth2-encrypt-to)
	 (token (oauth2-auth-and-store auth-url token-url resource-url
				       client-id client-secret redirect-uri)))
    (ext-oauth2-refresh-access token auth-url resource-url redirect-uri)
    token))

(defun ext-oauth2-access-token (host user auth-url token-url resource-url
				     client-id client-secret)
  "Get access token for OAUTH2."
  (let ((token (ext-oauth2-auth-and-refresh host user
					    auth-url token-url resource-url
					    client-id client-secret)))
    (oauth2-token-access-token token)))

(defconst ext-oauth2-gmail-props
  ;; Get from
  ;; https://accounts.google.com/.well-known/openid-configuration and
  ;; https://developers.google.com/identity/protocols/googlescopes
  '(:auth-url "https://accounts.google.com/o/oauth2/v2/auth"
	      :token-url "https://oauth2.googleapis.com/token"
	      :scope "https://mail.google.com/"))
(defconst ext-oauth2-mail-ru-props
  '(:auth-url "https://o2.mail.ru/login"
	      :token-url "https://o2.mail.ru/token"
	      :scope "mail.imap"))
(defconst ext-oauth2-yandex-imap-props
  '(:auth-url "https://oauth.yandex.com/authorize"
	      :token-url "https://oauth.yandex.com/token"
	      :scope "mail:imap_full"))
(defconst ext-oauth2-yandex-smtp-props
  '(:auth-url "https://oauth.yandex.com/authorize"
	      :token-url "https://oauth.yandex.com/token"
	      :scope "mail:smtp"))
(defconst ext-oauth2-yahoo-com-props
  '(:auth-url "https://api.login.yahoo.com/oauth2/request_auth"
	      :token-url "https://api.login.yahoo.com/oauth2/get_token"
	      :scope "mail-w"))
(defconst ext-oauth2-aol-props
  '(:auth-url "https://api.login.aol.com/oauth2/request_auth"
	      :token-url "https://api.login.aol.com/oauth2/get_token"
	      :scope "mail-w"))

(defcustom ext-oauth2-issuers-alist
  `(("imap.googlemail.com" . ,ext-oauth2-gmail-props)
    ("smtp.googlemail.com" . ,ext-oauth2-gmail-props)
    ("imap.gmail.com" . ,ext-oauth2-gmail-props)
    ("smtp.gmail.com" . ,ext-oauth2-gmail-props)

    ("imap.mail.ru" . ,ext-oauth2-mail-ru-props)
    ("smtp.mail.ru" . ,ext-oauth2-mail-ru-props)

    ("imap.yandex.com" . ,ext-oauth2-yandex-imap-props)
    ("smtp.yandex.com" . ,ext-oauth2-yandex-smtp-props)

    ("imap.mail.yahoo.com" . ,ext-oauth2-yahoo-com-props)
    ("smtp.mail.yahoo.com" . ,ext-oauth2-yahoo-com-props)

    ("imap.aol.com" . ,ext-oauth2-aol-props)
    ("smtp.aol.com" . ,ext-oauth2-aol-props))
  "The alist of endpoint URLs for OAUTH2."
  :type '(alist :key-type string :value-type list))

;; xoauth2 backend for auth-source

;;(defcustom auth-source-xoauth2-creds
;;  '(("example.gmail.com"
;;     (:auth-url "https://accounts.google.com/o/oauth2/v2/auth"
;;      :token-url "https://oauth2.googleapis.com/token"
;;      :scope "https://mail.google.com/"
;;      :client-id "<client-id.apps.googleusercontent.com>"
;;      :client-secret "<client-secret>")))
(defcustom auth-source-xoauth2-creds #'auth-source-xoauth2-pass-creds
  "A property list containing values for the following XOAuth2 keys:
:auth-url, :token-url, :scope, :client-id, and :client-secret.

If this is set to a string, it is considered the name of a file
containing one sexp that evaluates to either the property list above,
or to a hash table containing (HOST USER PORT) keys mapping to
property lists as above. Note that the hash table /must/ have its
`:test' property set to `equal'. Example:

    #s(hash-table size 2 test equal
       data ((\"host1.com\" \"user1\" \"port1\")
             (:auth-url \"auth-url-1\"
              :token-url \"token-url-1\"
              :scope \"scope-1\"
              :client-id \"client-id-1\"
              :client-secret \"client-secret-1\")

             (\"host2.com\" \"user2\" \"port2\")
             (:auth-url \"auth-url-2\"
              :token-url \"token-url-2\"
              :scope \"scope-2\"
              :client-id \"client-id-2\"
              :client-secret \"client-secret-2\")))

If this is set to a function, it will be called with HOST, USER, and
PORT values, and should return the respective property list.

This package provides a function that retrieves the values from a
password-store.  See `auth-source-xoauth2-pass-creds' for details."
  :type '(choice string function list))

(defun auth-source-xoauth2-pass-creds (host user port)
  "Retrieve a XOAUTH2 access token using `auth-source-pass'.
This function retrieve a password-store entry matching HOST, USER, and
PORT. This entry should contain the following key-value pairs:

<client-secret>
username: <client-id>
auth-url: <value>
token-url: <value>
scope: <value>

which are used to build and return the property list required by
`auth-source-xoauth2-creds'."
  (when-let ((entry-data (auth-source-pass--find-match host user port)))
    (when-let ((auth-url (auth-source-pass--get-attr "auth-url" entry-data))
	       (token-url (auth-source-pass--get-attr "token-url" entry-data))
	       (scope (auth-source-pass--get-attr "scope" entry-data))
               (client-id (auth-source-pass--get-attr "user" entry-data))
               (client-secret (auth-source-pass--get-attr 'secret entry-data)))
      (list :auth-url auth-url :token-url token-url :scope scope
	    :client-id client-id :client-secret client-secret))))

(defun auth-source-xoauth2--file-creds (file host user port)
  "Load FILE and evaluate it, matching entries to HOST, USER, and PORT."
  (when (not (string= "gpg" (file-name-extension file)))
    (error "The auth-source-xoauth2-creds file must be GPG encrypted"))
  (when-let
      ((creds (condition-case err
                  (eval (with-temp-buffer
                          (insert-file-contents file)
                          (goto-char (point-min))
                          (read (current-buffer)))
                        t)
                (error
                 "Error parsing contents of %s: %s"
                 file (error-message-string err)))))
    (cond
     ((hash-table-p creds)
      (message "Searching hash table for (%S %S %S)" host user port)
      (gethash `(,host ,user ,port) creds))
     (creds))))

(defun auth-source-xoauth2--alist-creds (host)
  "Matching entries to HOST from alist."
  (when-let ((entry (assoc host auth-source-xoauth2-creds)))
    (cadr entry)))

(cl-defun auth-source-xoauth2--search (host user port)
  "Get the XOAUTH2 authentication data for the given HOST, USER, and PORT."
  (when-let ((token
              (cond
               ((functionp auth-source-xoauth2-creds)
                (funcall auth-source-xoauth2-creds host user port))
               ((stringp auth-source-xoauth2-creds)
                (auth-source-xoauth2--file-creds
                 auth-source-xoauth2-creds host user port))
               (t
		(auth-source-xoauth2--alist-creds host)))))
    (when-let ((auth-url (plist-get token :auth-url))
	       (token-url (plist-get token :token-url))
	       (scope (plist-get token :scope))
               (client-id (plist-get token :client-id))
               (client-secret (plist-get token :client-secret)))
      (list :host host :port port :user user
	    :secret (lambda ()
		      (ext-oauth2-access-token host user
					       auth-url token-url scope
					       client-id client-secret))))))

(cl-defun auth-source-xoauth2-search (&rest spec
                                            &key backend type host user port
                                            &allow-other-keys)
  "Given a property list SPEC, return search matches from the :backend.
See `auth-source-search' for details on SPEC."
  ;; just in case, check that the type is correct (null or same as the backend)
  (cl-assert (or (null type) (eq type (oref backend type)))
             t "Invalid xoauth2 search: %s %s")
  (let* ((hosts (if (and host (listp host)) host `(,host)))
         (ports (if (and port (listp port)) port `(,port))))
    (catch 'match
      (dolist (host hosts)
        (dolist (port ports)
          (let ((match (auth-source-xoauth2--search host user port)))
	    (when match
	      (throw 'match `(,match)))))))))

(defvar auth-source-xoauth2-backend
  (auth-source-backend
   (when (<= emacs-major-version 25) "xoauth2")
   :source "." ;; not used
   :type 'xoauth2
   :search-function #'auth-source-xoauth2-search)
  "Auth-source backend for XOAUTH2.")

(defun auth-source-xoauth2-backend-parse (entry)
  "Create a XOAUTH2 auth-source backend from ENTRY."
  (when (eq entry 'xoauth2)
    (auth-source-backend-parse-parameters entry auth-source-xoauth2-backend)))

(add-hook 'auth-source-backend-parser-functions
	  #'auth-source-xoauth2-backend-parse)

;; nnimap and smtp hook for xoauth2
(defun gnus-xoauth2-token (user access-token)
  "Make base64 string for XOAUTH2 authentication from USER and ACCESS-TOKEN."
  (base64-encode-string (format "user=%s\001auth=Bearer %s\001\001"
				user access-token)
			t))

(defvar nnimap-object)
(declare-function nnimap-wait-for-line "nnimap"
		  (regexp &optional response-regexp))
(declare-function nnimap-send-command "nnimap" (&rest args))
(declare-function nnimap-get-response "nnimap" (sequence))
(declare-function nnimap-newlinep "nnimap" (object))
(declare-function nnheader-report "nnheader" (backend &rest args))
(defun gnus-xoauth2-nnimap-xoauth-command (user access-token)
  "Send XOAUTH2 command with USER and ACCESS-TOKEN."
  (erase-buffer)
  (let ((sequence (nnimap-send-command "AUTHENTICATE XOAUTH2 %s"
				       (gnus-xoauth2-token user access-token)))
	(challenge (nnimap-wait-for-line "^\\(.*\\)\n")))
    ;; on error response, "+ <base64 string>".
    (if (not (string-match "^\\+ [a-zA-Z0-9+/=]+" challenge))
	(cons t (nnimap-get-response sequence))
      ;; send empty response on error
      (let (response)
	(erase-buffer)
	(process-send-string (get-buffer-process (current-buffer))
			     (if (nnimap-newlinep nnimap-object)
				 "\n"
			       "\r\n"))
	(setq response (nnimap-get-response sequence))
	(nnheader-report 'nnimap "%s"
			 (mapconcat (lambda (a)
				      (format "%s" a))
				    (car response) " "))
	nil))))

(defvar nnimap-authenticator)
(declare-function nnimap-capability "nnimap" (capability))
(defun gnus-xoauth2-nnimap-login (fn user password)
  (if (and (eq nnimap-authenticator 'xoauth2)
	   (nnimap-capability "AUTH=XOAUTH2")
	   (nnimap-capability "SASL-IR"))
      (gnus-xoauth2-nnimap-xoauth-command user password)
    (funcall fn user password)))

(defvar smtpmail-auth-supported)
(declare-function smtpmail-command-or-throw "smtpmail"
		  (process string &optional code))
(cl-defmethod smtpmail-try-auth-method
  (process (_mech (eql xoauth2)) user password)
  (smtpmail-command-or-throw
   process
   (concat "AUTH XOAUTH2 " (gnus-xoauth2-token user password))
   235))

;;;###autoload
(defun gnus-xoauth2-enable ()
  "Enable auth-source-xoauth2."
  (interactive)

  ;; Add functionality to nnimap-login
  (with-eval-after-load "nnimap"
    (advice-add 'nnimap-login :around #'gnus-xoauth2-nnimap-login))
  ;; Add the functionality to smtpmail-try-auth-method
  (with-eval-after-load "smtpmail"
    (add-to-list 'smtpmail-auth-supported 'xoauth2))

  ;; To add password-store to the list of sources, evaluate the following:
  (add-to-list 'auth-sources 'xoauth2)
  ;; clear the cache (required after each change to #'auth-source-pass-search)
  (auth-source-forget-all-cached))

(provide 'gnus-xoauth2)
;;; gnus-xoauth2.el ends here

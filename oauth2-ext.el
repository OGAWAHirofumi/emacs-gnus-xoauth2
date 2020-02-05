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
;; error handling, and password-store.

;;; Code:

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

(defun oauth2-ext-compute-id (auth-url token-url resource-url
				       &rest keys)
  "Compute an unique id based on URLs.
The unique id is made from AUTH-URL, TOKEN-URL, RESOURCE-URL, and KEYS.
This allows to store the token in an unique way."
  (secure-hash 'md5 (apply #'concat auth-url token-url resource-url keys)))

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
      (let ((token (oauth2-auth auth-url token-url
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
If refresh returned error, restart from `oauth2-auth' with
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
      ;; if refresh was error, restart from `oauth2-auth'
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

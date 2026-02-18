"""
Google Drive upload — two authentication modes.

────────────────────────────────────────────────────────────────
MODE 1 (recommended): OAuth2 Device Flow  ← configure on the web
────────────────────────────────────────────────────────────────
No JSON files, no pip installs.  Pure stdlib (urllib).

Quick setup:
  1. Google Cloud Console → New project
  2. APIs & Services → Enable → "Google Drive API"
  3. APIs & Services → Credentials → Create → OAuth 2.0 Client IDs
     Application type: "TV and Limited Input devices"
  4. Copy Client ID and Client Secret → paste into the web UI
     (Recordings page → Google Drive section → Connect)
  5. A code appears — visit the link on ANY device and type the code
  6. Done.  Tokens auto-refresh forever.

────────────────────────────────────────────────────────────────
MODE 2 (legacy): Service Account JSON
────────────────────────────────────────────────────────────────
Requires: pip3 install google-api-python-client google-auth
Used automatically when DVR_GDRIVE_CREDENTIALS is set and no OAuth
token is present.
"""

import os
import json
import time
import logging
import urllib.request
import urllib.parse
import urllib.error

log = logging.getLogger('dvr.gdrive')

_DEVICE_AUTH_URL = 'https://oauth2.googleapis.com/device/code'
_TOKEN_URL       = 'https://oauth2.googleapis.com/token'
_DRIVE_FILES_URL = 'https://www.googleapis.com/drive/v3/files'
_DRIVE_UPLOAD_URL= 'https://www.googleapis.com/upload/drive/v3/files'
_SCOPE           = 'https://www.googleapis.com/auth/drive.file'


# ── Helpers ───────────────────────────────────────────────────────────────────

def _post_form(url, data):
    body = urllib.parse.urlencode(data).encode()
    req  = urllib.request.Request(url, data=body,
              headers={'Content-Type': 'application/x-www-form-urlencoded'})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read())


def _api_get(url, token, params=None):
    if params:
        url += '?' + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={'Authorization': f'Bearer {token}'})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read())


def _api_post_json(url, token, body):
    data = json.dumps(body).encode()
    req  = urllib.request.Request(url, data=data, headers={
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json',
    })
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read())


# ═══════════════════════════════════════════════════════════════════════════════
# MODE 1 — OAuth Device Flow  (pure stdlib, no pip install needed)
# ═══════════════════════════════════════════════════════════════════════════════

class OAuthDriveUploader:
    """Headless OAuth2 device-flow uploader.  Pure stdlib — no pip needed."""

    def __init__(self, token_path, client_id='', client_secret='', folder_id=''):
        self._token_path   = token_path
        self.client_id     = client_id
        self.client_secret = client_secret
        self.folder_id     = folder_id
        self._token        = None
        self._subfolder_cache = {}
        if os.path.isfile(token_path):
            self._load_token()

    # ── Token management ──────────────────────────────────────────────────────

    def _load_token(self):
        try:
            with open(self._token_path) as f:
                self._token = json.load(f)
        except Exception:
            self._token = None

    def _save_token(self):
        try:
            os.makedirs(os.path.dirname(self._token_path), exist_ok=True)
            with open(self._token_path, 'w') as f:
                json.dump(self._token, f)
        except OSError as e:
            log.error('Could not save token: %s', e)

    def _refresh_access_token(self):
        if not self._token or not self._token.get('refresh_token'):
            raise RuntimeError('Not authenticated — complete OAuth flow first')
        resp = _post_form(_TOKEN_URL, {
            'client_id':     self.client_id,
            'client_secret': self.client_secret,
            'refresh_token': self._token['refresh_token'],
            'grant_type':    'refresh_token',
        })
        if 'error' in resp:
            raise RuntimeError(f'Token refresh failed: {resp}')
        self._token['access_token'] = resp['access_token']
        self._token['expires_at']   = time.time() + resp.get('expires_in', 3600)
        self._save_token()

    def _access_token(self):
        if not self._token:
            raise RuntimeError('Not authenticated')
        if time.time() > self._token.get('expires_at', 0) - 60:
            self._refresh_access_token()
        return self._token['access_token']

    @property
    def is_authenticated(self):
        return bool(self._token and self._token.get('refresh_token'))

    # ── Device flow steps (called from web API) ───────────────────────────────

    @classmethod
    def start_device_auth(cls, client_id, client_secret):
        """
        Step 1: request a device code.
        Returns: {device_code, user_code, verification_url, expires_in, interval}
        """
        resp = _post_form(_DEVICE_AUTH_URL, {'client_id': client_id, 'scope': _SCOPE})
        if 'error' in resp:
            raise RuntimeError(f'Device auth start failed: {resp.get("error_description", resp)}')
        return resp

    @classmethod
    def poll_token(cls, client_id, client_secret, device_code):
        """
        Step 2 (poll until approved).
        Returns token dict on approval, None if still pending, raises on error/expiry.
        """
        resp = _post_form(_TOKEN_URL, {
            'client_id':     client_id,
            'client_secret': client_secret,
            'device_code':   device_code,
            'grant_type':    'urn:ietf:params:oauth:grant-type:device_code',
        })
        if resp.get('error') == 'authorization_pending':
            return None
        if resp.get('error') == 'slow_down':
            return None
        if 'error' in resp:
            raise RuntimeError(f'OAuth error: {resp["error"]} — {resp.get("error_description", "")}')
        return resp

    def store_token(self, token_resp):
        """Save a newly obtained token response."""
        self._token = {
            'access_token':  token_resp['access_token'],
            'refresh_token': token_resp.get('refresh_token', ''),
            'expires_at':    time.time() + token_resp.get('expires_in', 3600),
        }
        self._save_token()
        log.info('Google Drive: OAuth token saved')

    def revoke(self):
        """Revoke and delete the stored token."""
        if self._token and self._token.get('access_token'):
            try:
                url = ('https://oauth2.googleapis.com/revoke?token='
                       + urllib.parse.quote(self._token['access_token']))
                urllib.request.urlopen(
                    urllib.request.Request(url, method='POST'), timeout=5)
            except Exception:
                pass
        self._token = None
        try:
            os.remove(self._token_path)
        except FileNotFoundError:
            pass
        log.info('Google Drive: token revoked')

    # ── Drive API ─────────────────────────────────────────────────────────────

    def upload(self, filepath, filename=None, folder_id=None):
        """Upload file via resumable upload. Returns Drive file ID."""
        if filename is None:
            filename = os.path.basename(filepath)
        parent = folder_id or self.folder_id
        token  = self._access_token()
        fsize  = os.path.getsize(filepath)

        meta = {'name': filename}
        if parent:
            meta['parents'] = [parent]

        # Initiate resumable session
        meta_bytes = json.dumps(meta).encode()
        init_req   = urllib.request.Request(
            _DRIVE_UPLOAD_URL + '?uploadType=resumable',
            data=meta_bytes,
            headers={
                'Authorization':           f'Bearer {token}',
                'Content-Type':            'application/json',
                'X-Upload-Content-Type':   'application/octet-stream',
                'X-Upload-Content-Length': str(fsize),
            },
        )
        with urllib.request.urlopen(init_req, timeout=30) as r:
            session_url = r.headers.get('Location')
        if not session_url:
            raise RuntimeError('No session URI from Drive — check credentials / folder ID')

        # Upload in 4 MB chunks
        CHUNK    = 4 * 1024 * 1024
        uploaded = 0
        file_id  = None
        with open(filepath, 'rb') as f:
            while uploaded < fsize:
                chunk = f.read(CHUNK)
                if not chunk:
                    break
                end = uploaded + len(chunk) - 1
                put = urllib.request.Request(
                    session_url, data=chunk, method='PUT',
                    headers={
                        'Content-Length': str(len(chunk)),
                        'Content-Range':  f'bytes {uploaded}-{end}/{fsize}',
                    })
                try:
                    with urllib.request.urlopen(put, timeout=120) as r:
                        if r.status == 200:
                            file_id = json.loads(r.read()).get('id')
                except urllib.error.HTTPError as e:
                    if e.code == 308:   # Resume Incomplete — expected for non-final chunks
                        pass
                    else:
                        raise
                uploaded += len(chunk)

        log.info('Uploaded %s → Drive (id=%s)', filename, file_id)
        return file_id

    def ensure_subfolder(self, name, parent_id=None):
        """Get or create subfolder. Cached."""
        if name in self._subfolder_cache:
            return self._subfolder_cache[name]
        parent = parent_id or self.folder_id
        if not parent:
            return None
        token = self._access_token()
        q = (f"name='{name}' and '{parent}' in parents "
             f"and mimeType='application/vnd.google-apps.folder' and trashed=false")
        resp = _api_get(_DRIVE_FILES_URL, token, {'q': q, 'fields': 'files(id)'})
        files = resp.get('files', [])
        if files:
            fid = files[0]['id']
        else:
            result = _api_post_json(_DRIVE_FILES_URL, token, {
                'name': name,
                'mimeType': 'application/vnd.google-apps.folder',
                'parents': [parent],
            })
            fid = result['id']
            log.info('Created Drive subfolder: %s (%s)', name, fid)
        self._subfolder_cache[name] = fid
        return fid


# ═══════════════════════════════════════════════════════════════════════════════
# MODE 2 — Service Account JSON  (legacy, requires pip install)
# ═══════════════════════════════════════════════════════════════════════════════

class GDriveUploader:
    """Legacy service-account uploader. Requires google-api-python-client."""

    def __init__(self, credentials_file, folder_id=None):
        try:
            from google.oauth2 import service_account
            from googleapiclient.discovery import build
            from googleapiclient.http import MediaFileUpload
            self._MediaUpload = MediaFileUpload
        except ImportError:
            raise RuntimeError(
                'google-api-python-client not installed.\n'
                'Run:  pip3 install google-api-python-client google-auth\n'
                'Or use OAuth2 (web UI) instead — no pip needed.'
            )
        if not os.path.isfile(credentials_file):
            raise FileNotFoundError(f'Credentials file not found: {credentials_file}')

        creds = service_account.Credentials.from_service_account_file(
            credentials_file,
            scopes=['https://www.googleapis.com/auth/drive.file'],
        )
        self._service  = build('drive', 'v3', credentials=creds, cache_discovery=False)
        self.folder_id = folder_id
        self._subfolder_cache = {}
        log.info('Google Drive (service account): %s', creds.service_account_email)

    @property
    def is_authenticated(self):
        return True

    def upload(self, filepath, filename=None, folder_id=None):
        if filename is None:
            filename = os.path.basename(filepath)
        parent = folder_id or self.folder_id
        meta   = {'name': filename}
        if parent:
            meta['parents'] = [parent]
        media  = self._MediaUpload(filepath, resumable=True)
        result = self._service.files().create(
            body=meta, media_body=media, fields='id').execute()
        log.info('Uploaded %s → Drive (service-account)', filename)
        return result['id']

    def ensure_subfolder(self, name, parent_id=None):
        if name in self._subfolder_cache:
            return self._subfolder_cache[name]
        parent = parent_id or self.folder_id
        if not parent:
            return None
        q = (f"name='{name}' and '{parent}' in parents "
             f"and mimeType='application/vnd.google-apps.folder' and trashed=false")
        hits  = self._service.files().list(q=q, fields='files(id)').execute()
        files = hits.get('files', [])
        if files:
            fid = files[0]['id']
        else:
            fid = self._service.files().create(body={
                'name': name,
                'mimeType': 'application/vnd.google-apps.folder',
                'parents': [parent],
            }, fields='id').execute()['id']
        self._subfolder_cache[name] = fid
        return fid

from flask import Flask, request, jsonify
from google.oauth2 import service_account
from google.auth.transport.requests import Request
from google.auth.oauthlib.flow import InstalledAppFlow
from google.api_core import retry
import google.auth.transport.requests
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import anthropic
import os
import json
from pathlib import Path
from typing import Optional
import logging

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# SCOPES for Google Drive API
SCOPES = ['https://www.googleapis.com/auth/drive.readonly']

def get_drive_service():
    """Authenticate and return Google Drive service."""
    try:
        # Try to use service account from env variable
        creds_json = os.getenv('GOOGLE_APPLICATION_CREDENTIALS_JSON')
        if creds_json:
            creds_dict = json.loads(creds_json)
            creds = service_account.Credentials.from_service_account_info(
                creds_dict, scopes=SCOPES
            )
        else:
            # Fall back to token.json
            creds = None
            if Path('token.json').exists():
                from google.auth.transport.requests import Request
                from google.oauth2.credentials import Credentials
                creds = Credentials.from_authorized_user_file('token.json', SCOPES)
            
            if not creds or not creds.valid:
                if creds and creds.expired and creds.refresh_token:
                    creds.refresh(Request())
                else:
                    # This would need client_secret.json for full auth
                    raise ValueError("No valid credentials found")
        
        return build('drive', 'v3', credentials=creds)
    except Exception as e:
        logger.error(f"Error authenticating: {e}")
        raise

def classify_file(filename: str, file_id: str, mime_type: str) -> dict:
    """Use Claude to classify file by name and metadata."""
    try:
        client = anthropic.Anthropic(api_key=os.getenv('ANTHROPIC_API_KEY'))
        
        classification_prompt = f"""
Classify this file and determine its category:
Filename: {filename}
MIME Type: {mime_type}
File ID: {file_id}

Categories: Prompts, Fonts, Courses, E-books, Templates, Tools, Images, Videos, Audio, Documents, Other

Respond with JSON:
{{
  "category": "one_of_above",
  "confidence": 0.0_to_1.0,
  "tags": ["tag1", "tag2"],
  "description": "brief_desc"
}}
"""
        
        message = client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=1024,
            messages=[
                {"role": "user", "content": classification_prompt}
            ]
        )
        
        # Parse response
        response_text = message.content[0].text
        # Extract JSON from response
        import re
        json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
        if json_match:
            classification = json.loads(json_match.group())
            return classification
        else:
            return {
                "category": "Other",
                "confidence": 0.5,
                "tags": ["unclassified"],
                "description": "Could not classify"
            }
    except Exception as e:
        logger.error(f"Error classifying {filename}: {e}")
        return {
            "category": "Other",
            "confidence": 0,
            "tags": ["error"],
            "description": str(e)
        }

def scan_drive_folder(folder_id: str = None) -> list:
    """Scan Google Drive for PDFs and ZIPs, classify them."""
    try:
        service = get_drive_service()
        files = []
        
        # Query for PDFs and ZIPs
        query = "(mimeType='application/pdf' OR mimeType='application/zip' OR mimeType='application/x-zip-compressed') and trashed=false"
        
        if folder_id:
            query += f" and parents='{folder_id}'"
        
        request = service.files().list(
            q=query,
            spaces='drive',
            fields='files(id, name, mimeType, createdTime, modifiedTime, size)',
            pageSize=100
        )
        
        while request:
            try:
                results = request.execute()
                for file in results.get('files', []):
                    # Classify the file
                    classification = classify_file(
                        filename=file['name'],
                        file_id=file['id'],
                        mime_type=file['mimeType']
                    )
                    
                    file['classification'] = classification
                    files.append(file)
                
                request = service.files().list_next(request, results)
            except HttpError as error:
                logger.error(f'An error occurred: {error}')
                break
        
        return files
    except Exception as e:
        logger.error(f"Error scanning drive: {e}")
        return []

@app.route('/api/scan', methods=['POST'])
def scan_endpoint():
    """Endpoint to scan Google Drive and return classified files."""
    try:
        data = request.get_json() or {}
        folder_id = data.get('folder_id')
        
        # Scan drive
        files = scan_drive_folder(folder_id)
        
        return jsonify({
            'status': 'success',
            'files_found': len(files),
            'files': files
        })
    except Exception as e:
        logger.error(f"Endpoint error: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({'status': 'healthy'})

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=int(os.getenv('PORT', 3000)))

from flask import Flask, request, render_template
import requests
import hashlib
import os

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB

def calculate_hash(file_stream):
    """Calculate SHA256 hash from file stream"""
    file_hash = hashlib.sha256()
    while chunk := file_stream.read(65536):  # Read in 64k chunks
        file_hash.update(chunk)
    file_stream.seek(0)  # Reset stream position for potential future reads
    return file_hash.hexdigest()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload():
    if 'file' not in request.files:
        return "No file part", 400
    
    file = request.files['file']
    if file.filename == '':
        return "No selected file", 400
    
    if file:
        # Calculate hash directly from the file stream
        hash_value = calculate_hash(file.stream)
        
        # Get API key
        api_key = open('.env').read().strip()
        url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
        headers = {
            "accept": "application/json",
            "x-apikey": api_key
        }

        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            attributes = data['data']['attributes']
            result_data = {
                "file_size": attributes['size'],
                "file_type": attributes['type_extension'],
                "file_name": attributes['meaningful_name'],
                "times_submitted": attributes['times_submitted'],
                "sha256": attributes['sha256'],
                "engines_detected": attributes['last_analysis_stats']['malicious'],
                "undetected_engines": attributes['last_analysis_stats']['undetected'],
                "engine_results": []
            }

            engine_results = attributes.get('last_analysis_results', {})
            for engine, result in engine_results.items():
                if result.get('category') == 'malicious':
                    method = result.get('method')
                    engine_name = result.get('engine_name')
                    engine_version = result.get('engine_version')
                    category = result.get('category')
                    results = result.get('result')

                    result_data['engine_results'].append({
                        "method": method,
                        "engine_name": engine_name,
                        "engine_version": engine_version,
                        "category": category,
                        "result": results if results else 'No Results'
                    })

            return render_template('result.html', result=result_data)
        else:
            return f"Error: {response.status_code} - {response.json().get('error', {}).get('message', 'Unknown error')}", 400

if __name__ == '__main__':
    app.run(debug=True)

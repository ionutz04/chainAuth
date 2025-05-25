from http import client
from flask import Flask, request, jsonify
import hashlib
from OpenSSL import crypto
import os
import json
import base64
from dotenv import load_dotenv
import logging

app = Flask(__name__)
logging.basicConfig(level=logging.DEBUG)
load_dotenv()

class Block:
    def __init__(self, data, previous_hash):
        self.data = data
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        return hashlib.sha256(
            f"{json.dumps(self.data, sort_keys=True)}{self.previous_hash}".encode()
        ).hexdigest()

blockchain = []

@app.route('/data', methods=['POST'])
def handle_data():
    try:
        # Get raw request data for debugging
        raw_data = request.get_data(as_text=True)
        app.logger.debug(f"Raw received data: {raw_data}")
        
        payload = json.loads(raw_data)
        data = payload['data']
        signature = base64.b64decode(payload['signature'])

        # Construct absolute key path
        pub_key_path = os.path.expanduser(
            "~/Dropbox/facultate/an2/FILS/OS2/chainAuth/BlockchainAuthentication/keys/" 
            f"{data['sensor_type']}_public.pem"
        )
        
        app.logger.debug(f"Full key path: {os.path.abspath(pub_key_path)}")
        
        if not os.path.exists(pub_key_path):
            return jsonify({"error": "Public key not found"}), 404

        # Load public key with proper error handling
        with open(pub_key_path, "r") as f:
            try:
                pub_key = crypto.load_publickey(crypto.FILETYPE_PEM, f.read())
                content = f.read()
                app.logger.debug("Key file content:\n%s", content)
            except Exception as e:
                app.logger.error(f"Failed to load public key: {str(e)}")
                return jsonify({"error": "Invalid public key format"}), 400

        # Create certificate object
        cert = crypto.X509()
        cert.set_pubkey(pub_key)

        # Serialize data identically to C++ code
        data_str = json.dumps(data, sort_keys=True, separators=(',', ':'))
        app.logger.debug(f"Data being verified: {data_str}")
        
        # Create digest
        digest = hashlib.sha256(data_str.encode()).digest()
        app.logger.debug(f"SHA256 digest: {digest.hex()}")

        # Verify signature
        try:
            crypto.verify(cert, signature, digest, "sha256")
            app.logger.debug("Signature valid")
        except crypto.Error as e:
            app.logger.error(f"Signature verification failed: {str(e)}")
            app.logger.debug(f"Signature bytes: {signature.hex()}")
            return jsonify({"error": "Invalid signature"}), 401

        # Add to blockchain
        prev_hash = blockchain[-1].hash if blockchain else "0"
        block = Block(data, prev_hash)
        blockchain.append(block)
        
        return jsonify({"status": "success"}), 200

    except Exception as e:
        app.logger.error(f"Error processing request: {str(e)}", exc_info=True)
        return jsonify({"error": str(e)}), 500

@app.route('/analyze', methods=['GET'])
def analyze():
    try:
        if not blockchain:
            return jsonify({"error": "No data available"}), 404

        latest = blockchain[-1].data
        prompt = f"Temperature: {latest.get('value', 'N/A')}°C. Is this environment suitable for learning?"
        
        response = client.chat.completions.create(
            model="llama-3.1-sonar-small-128k-online",
            messages=[
                {"role": "system", "content": "You are an environmental analysis assistant."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3,
            max_tokens=60
        )
        
        return jsonify({
            "analysis": response.choices[0].message.content.strip(),
            "sensor_data": latest
        })

    except Exception as e:
        app.logger.error(f"Analysis error: {str(e)}")
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

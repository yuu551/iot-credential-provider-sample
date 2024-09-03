import time
import json
from AWSIoTPythonSDK.MQTTLib import AWSIoTMQTTClient
import boto3
import json
import http.client
import ssl
import sys
import os
import base64

# エンドポイントの定義
iot_endpoint = "${iot_endpoint}"
iot_cred_endpoint = "${iot_cred_endpoint}"
# アップロード先のバケット
target_bucket_name = "${target_bucket_name}"

# MQTTクライアントの作成
myMQTTClient = AWSIoTMQTTClient("example-thing")
myMQTTClient.configureEndpoint(iot_endpoint, 8883)

# 認証情報の設定
myMQTTClient.configureCredentials(
    "/home/ec2-user/root-ca.pem",
    "/home/ec2-user/private.key",
    "/home/ec2-user/certificate.pem"
)

# IoT Coreへ接続
myMQTTClient.connect()

# ファイルサイズの閾値（50KB）
SIZE_THRESHOLD = 51200

def get_file_size(file_path):
    return os.path.getsize(file_path)

def upload_s3(file_path):
    file_size = get_file_size(file_path)

    if file_size > SIZE_THRESHOLD:
        # ファイルサイズが閾値を超える場合、S3にアップロード
        context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        context.load_cert_chain("/home/ec2-user/certificate.pem", "/home/ec2-user/private.key")
        context.load_verify_locations("/home/ec2-user/root-ca.pem")
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True

        headers = {
            "x-amzn-iot-thingname": "example-thing"
        }

        conn = http.client.HTTPSConnection(iot_cred_endpoint, port=443, context=context)
        # 認証情報プロバイダーとIoTエイリアスに紐づくURLからトークンを取得
        conn.request("GET", "/role-aliases/${alies_role}/credentials", headers=headers)
        response = conn.getresponse()
        credential_data = json.loads(response.read())

        # 取得した認証情報からS3クライアントを作成
        s3 = boto3.client("s3",aws_access_key_id=credential_data['credentials']['accessKeyId'], 
            aws_secret_access_key=credential_data['credentials']['secretAccessKey'],
            aws_session_token=credential_data['credentials']['sessionToken'])
        file_name = os.path.basename(file_path)
        s3.upload_file(file_path, target_bucket_name, file_name)

        # S3からURLを取得
        s3_url = f"https://{target_bucket_name}.s3.amazonaws.com/{file_name}"

        message = {"type": "s3_url", "url": s3_url}
        myMQTTClient.publish("file/upload", json.dumps(message), 1)
        print("Successfully sent file directly to S3")

    else:
        # ファイルサイズが閾値以下の場合、MQTTで直接送信
        with open(file_path, "rb") as file:
            file_content = file.read()
        file_content_base64 = base64.b64encode(file_content).decode('ascii')
        message = {
            "type": "file_content",
            "content": file_content_base64
        }

        myMQTTClient.publish("file/upload", json.dumps(message), 1)
        print("Successfully sent file directly via MQTT")

# スクリプトファイル実行時のメイン関数
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <file_name>")
        sys.exit(1)
    
    file_name = sys.argv[1]
    file_path = os.path.join(os.getcwd(), file_name)
    
    if not os.path.exists(file_path):
        print(f"Error: File '{file_name}' does not exist in the current directory.")
        sys.exit(1)
    
    upload_s3(file_path)
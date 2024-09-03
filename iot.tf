# IoT証明書を作成し、アクティブに設定
resource "aws_iot_certificate" "cert" {
  active = true
}

# IoTデバイス（Thing）を作成
resource "aws_iot_thing" "example" {
  name = "example-thing"
}

# IoTポリシーを作成
# このポリシーは特定のトピックに対する操作を許可
resource "aws_iot_policy" "pubsub" {
  name = "PubSubToSpecificTopic"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # 特定のクライアントの接続を許可
        Effect   = "Allow"
        Action   = ["iot:Connect"]
        Resource = ["arn:aws:iot:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:client/${aws_iot_thing.example.name}"]
      },
      {
        # 特定のトピックへの発行と受信を許可
        Effect   = "Allow"
        Action   = ["iot:Publish", "iot:Receive"]
        Resource = ["arn:aws:iot:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:topic/my/test/topic", "arn:aws:iot:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:topic/file/upload"]
      },
      {
        # 特定のトピックフィルターへのサブスクリプションを許可
        Effect   = "Allow"
        Action   = ["iot:Subscribe"]
        Resource = ["arn:aws:iot:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:topicfilter/my/test/topic"]
      },
      {
        # 認証情報プロパイダーの許可
        Effect   = "Allow"
        Action   = ["iot:AssumeRoleWithCertificate"]
        Resource = "${aws_iot_role_alias.this.arn}"
      }
    ]
  })
}

# ポリシーを証明書にアタッチ
resource "aws_iot_policy_attachment" "attach_policy_to_cert" {
  policy = aws_iot_policy.pubsub.name
  target = aws_iot_certificate.cert.arn
}

# 証明書をThingにアタッチ
resource "aws_iot_thing_principal_attachment" "attach_cert_to_thing" {
  principal = aws_iot_certificate.cert.arn
  thing     = aws_iot_thing.example.name
}

# 証明書情報を保存するためのSecrets Managerシークレットを作成
resource "aws_secretsmanager_secret" "iot_cert" {
  name                           = "iot_certificate_test"
  force_overwrite_replica_secret = true
  recovery_window_in_days        = 0
}

# 証明書情報をシークレットに保存
resource "aws_secretsmanager_secret_version" "iot_cert" {
  secret_id = aws_secretsmanager_secret.iot_cert.id
  secret_string = jsonencode({
    certificate_pem = aws_iot_certificate.cert.certificate_pem
    private_key     = aws_iot_certificate.cert.private_key
  })
}

# IoTのエンドポイントを取得
data "aws_iot_endpoint" "data" {
  endpoint_type = "iot:Data-ATS"
}

# IAMロールの作成（認証情報プロバイダー用）
resource "aws_iam_role" "iot_device" {
  name = "iot_device_role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "credentials.iot.amazonaws.com"
      }
    }]
  })
}

# S3バケットの作成
resource "aws_s3_bucket" "this" {
  bucket = "device-upload-file-sample-bucket-yjinn"
}

resource "aws_s3_bucket_public_access_block" "this" {
  bucket                  = aws_s3_bucket.this.bucket
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# S3へのアクセス許可ポリシー
resource "aws_iam_policy" "s3_iot_device_policy" {
  name        = "s3_put_policy"
  description = "putObject Policy from Device"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "s3:PutObject"
      ]
      Resource = "arn:aws:s3:::${aws_s3_bucket.this.bucket}/*"
    }]
  })
}

# ポリシーとロールの紐付け
resource "aws_iam_role_policy_attachment" "s3_put_policy_attachment" {
  role       = aws_iam_role.iot_device.name
  policy_arn = aws_iam_policy.s3_iot_device_policy.arn
}

# 認証情報プロバイダー用のロールエイリアス
resource "aws_iot_role_alias" "this" {
  alias    = "device-iot-role-alias"
  role_arn = aws_iam_role.iot_device.arn
}

# 認証情報プロバイダーのエンドポイントを取得する
data "aws_iot_endpoint" "credential" {
  endpoint_type = "iot:CredentialProvider"
}

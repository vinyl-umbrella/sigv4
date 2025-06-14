# AWS SigV4

## 概要
AWS Signature Version 4 を Go で再実装
挙動検証として AWS Lambda の `ListFunctions`, `Invoke` を実装

## 実行
```sh
cp .env.example .env
# write your AWS credentials to .env
source ./.env && go run ./main.go
```

## 参考
- [AWS Signature Version 4 公式ドキュメント](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv.html)
- [AWS Lambda API リファレンス](https://docs.aws.amazon.com/lambda/latest/api/)

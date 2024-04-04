Simple HTTP Server
=====

以下のAPIを持つシンプルなAPIサーバの実装  
- GET /health-check
- POST /login
- POST /logout
- GET /protected

実行環境構築
```sh
docker run --rm -it --volume ${PWD}:/app --publish 8080:8080 python:3 bash
python -m pip install -r requirements.txt
uvicorn server:app --reload --port 8080
```
http://localhost:8080/docs にアクセスでAPIドキュメントを閲覧

テスト
```sh
curl -X POST -H 'Content-Type: application/json' -d '{"username":"user","password":"user"}' localhost:8080/login -v
curl -H 'Cookie: ~~~' localhost:8080/protected -v
```


# Phát hành CSDL nhận diện

## Định dạng manifest

```json
{
  "version": "1.2.0",
  "build": 3,
  "published_at": "2026-06-20T00:00:00Z",
  "database_url": "https://cdn.example.com/webguardian/signatures-3.json",
  "sha256": "64-lowercase-hex-characters",
  "minimum_app_version": "1.1.0"
}
```

`build` phải tăng đơn điệu. `database_url` có thể là URL tuyệt đối hoặc tương đối với manifest. Runtime chỉ chấp nhận HTTPS; `file://` chỉ phục vụ unit test/local verification.

## Định dạng database

```json
{
  "version": "1.2.0",
  "build": 3,
  "published_at": "2026-06-20T00:00:00Z",
  "rules": [{
    "id": "unique-rule-id",
    "category": "webshell",
    "severity": "critical",
    "extensions": [".php"],
    "pattern": "regex",
    "description": "Human-readable detection"
  }],
  "hashes": [{
    "sha256": "64-hex",
    "severity": "critical",
    "description": "Known malicious sample"
  }],
  "filenames": ["known-shell.php"]
}
```

## Quy trình phát hành

1. Tăng `build` và cập nhật `version` trong database.
2. Chạy unit tests và compile toàn bộ regex.
3. Tạo SHA-256 từ đúng bytes sẽ được publish.
4. Upload database trước.
5. Cập nhật manifest với URL và SHA-256, sau đó publish manifest cuối cùng.
6. Kiểm tra từ một cài đặt sạch và một cài đặt đang ở build trước.

## Mô hình xác minh

Ứng dụng tải manifest qua HTTPS, tải database, so SHA-256, parse JSON, kiểm tra trường bắt buộc và compile từng regex. Chỉ sau khi mọi bước thành công, database mới được ghi thành tệp tạm và thay thế atomically. Bản cũ được giữ tại `signatures.previous.json`.

SHA-256 bảo vệ integrity theo manifest; nó không thay thế chữ ký số. Với môi trường enterprise, nên ký manifest bằng Ed25519 và pin public key trong app ở phiên bản tiếp theo.

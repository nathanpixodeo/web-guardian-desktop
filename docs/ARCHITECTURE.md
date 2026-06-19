# Kiến trúc WebGuardian Desktop

## Mục tiêu

WebGuardian là static application security scanner chạy cục bộ. Kiến trúc tách UI, scan engine, signature updater và dữ liệu người dùng để GUI không chặn, engine có thể kiểm thử độc lập và bản đóng gói chạy được từ thư mục read-only.

## Thành phần

```text
PyQt6 UI
  ├─ ScanWorker (QThread) ── Scanner
  ├─ UpdateWorker (QThread) ── SignatureVersion
  ├─ QuarantineManager
  ├─ HistoryStore
  └─ SettingsStore

Scanner
  ├─ discovery + exclusions + scan mode
  ├─ built-in signatures
  ├─ updateable JSON signatures + hashes + filenames
  ├─ CMS/configuration checks
  └─ progress/threat callbacks + cancellation event
```

## Luồng quét

1. UI chụp cấu hình hiện tại và tạo `ScanWorker`.
2. Engine nhận diện CMS, kiểm tra cấu hình cấp dự án.
3. Discovery duyệt cây thư mục, cắt exclusion/symlink/tệp quá lớn và xác định tổng số candidate.
4. Mỗi tệp được băm SHA-256, loại binary, giải mã text và chạy rule phù hợp extension.
5. Progress và finding được phát qua Qt signals về GUI thread.
6. Cancellation dùng `threading.Event`; engine dừng ở ranh giới tệp.
7. Kết quả hoàn tất hoặc cancelled được ghi thành report JSON riêng.

## Dữ liệu người dùng

Windows: `%LOCALAPPDATA%\WebGuardian`

Linux: `$XDG_DATA_HOME/webguardian` hoặc `~/.local/share/webguardian`

```text
settings.json
signature_state.json
signatures.json
signatures.previous.json
reports/*.json
quarantine/index.json
quarantine/files/*.wgq
```

Ghi JSON quan trọng dùng tệp tạm, `fsync` và `os.replace` để tránh tệp dở dang khi mất điện hoặc ứng dụng bị dừng.

## Scan mode

- `quick`: chỉ extension rủi ro cao và tệp cấu hình quan trọng.
- `smart`: bỏ dependency, cache, build output, log và thư mục ẩn.
- `full`: chỉ luôn bỏ VCS, symlink và exclusion do người dùng đặt; mọi tệp trong giới hạn kích thước đều được xem xét.

## Threading

UI không cập nhật widget từ Python thread. `ScanWorker` và `UpdateWorker` là `QObject` chạy trong `QThread`; kết quả đi qua signal queued connection của Qt. Cancellation chỉ set event thread-safe.

## Phạm vi không hỗ trợ

Không có kernel driver, process memory scanning, packet inspection hoặc code execution sandbox. Backend FastAPI trong `backend/` là prototype cũ và không thuộc entry point desktop hiện tại.

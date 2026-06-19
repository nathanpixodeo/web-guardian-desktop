# WebGuardian Desktop

WebGuardian là ứng dụng desktop quét mã độc và lỗi cấu hình bảo mật trong mã nguồn. Giao diện PyQt6 chạy cục bộ trên Windows/Linux; mã nguồn được phân tích trên máy và không bị tải lên dịch vụ bên ngoài.

## Tính năng

- Dashboard trạng thái bảo vệ theo phong cách security suite chuyên nghiệp.
- Ba chế độ: Quick, Smart và Full scan.
- Nhận diện PHP, JavaScript/TypeScript, Python, Shell, HTML và cấu hình web.
- Kết hợp regex, tên backdoor đã biết và SHA-256 reputation nội bộ.
- Kiểm tra WordPress, Laravel, PrestaShop, `.env`, Composer, PHP ini và quyền tệp.
- Tiến độ theo tổng số tệp, live detection và hủy quét an toàn.
- Cách ly tệp, xác minh integrity trước khi khôi phục, xóa vĩnh viễn.
- Lưu lịch sử báo cáo, xem lại và xuất JSON.
- Exclusion theo đường dẫn/glob; giới hạn kích thước tệp và bật/tắt permission scan.
- CSDL nhận diện cập nhật qua HTTPS, xác minh SHA-256, kiểm tra schema/regex, cài atomically và giữ rollback.
- Dark/light theme và dữ liệu cấu hình bền vững theo tài khoản người dùng.

## Chạy ứng dụng

Yêu cầu Python 3.10 trở lên.

```powershell
python -m pip install -r requirements.txt
python main.py
```

Trên Linux, thay `python` bằng `python3` nếu cần.

## Cấu trúc

```text
main.py                         Entry point
webguardian/app.py              Khởi tạo QApplication
webguardian/ui/main_window.py   Dashboard và sáu màn hình chức năng
webguardian/scanner/core.py     Discovery, scan, progress và cancellation
webguardian/scanner/signatures.py Built-in rules + bộ nạp CSDL JSON
webguardian/scanner/version.py  Kiểm tra/cài/rollback CSDL
webguardian/quarantine.py       Cách ly, integrity và khôi phục
webguardian/storage.py          Settings và lịch sử báo cáo
assets/signatures.json          CSDL nhận diện đi kèm
assets/signatures_manifest.json Manifest phát hành mẫu
tests/                          Unit tests cho engine và dịch vụ
docs/                           Tài liệu kiến trúc/vận hành
```

## Cập nhật CSDL nhận diện

Mặc định ứng dụng đọc manifest từ repository chính. Có thể cấu hình endpoint riêng tại **Cài đặt → Máy chủ cập nhật**, hoặc dùng biến môi trường:

```powershell
$env:WEBGUARDIAN_UPDATE_URL = "https://security.example.com/webguardian/manifest.json"
python main.py
```

Manifest phải có `version`, `build`, `database_url` và SHA-256 dài 64 ký tự. Chi tiết ở [docs/SIGNATURE_UPDATES.md](docs/SIGNATURE_UPDATES.md).

## CLI / tích hợp engine

```python
from webguardian.scanner import Scanner

result = Scanner(
    "/path/to/project",
    scan_mode="smart",
    exclusions=["storage/cache/**"],
    max_file_size_mb=20,
).run()

print(result["summary"])
```

## Kiểm thử

```powershell
python -B -m unittest discover -s tests -v
```

## Đóng gói

```powershell
build_windows.bat
```

```bash
chmod +x build_linux.sh
./build_linux.sh
```

File đầu ra nằm trong `dist/`.

## Giới hạn an toàn

WebGuardian là static scanner cho mã nguồn, không thay thế EDR/antivirus cấp hệ điều hành. Ứng dụng không có kernel driver, real-time filesystem monitor, sandbox thực thi hay cloud reputation. Một phát hiện regex có thể là false positive; hãy xem ngữ cảnh trước khi xóa vĩnh viễn.

## License

MIT

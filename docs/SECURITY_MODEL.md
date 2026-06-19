# Mô hình bảo mật

## Tài sản cần bảo vệ

- Mã nguồn và cấu hình dự án.
- CSDL nhận diện cục bộ.
- Payload trong khu vực cách ly.
- Lịch sử finding có thể chứa đường dẫn nhạy cảm.

## Boundary

Mọi phân tích mã nguồn diễn ra cục bộ. Kết nối mạng chỉ dùng để lấy manifest/database khi người dùng kiểm tra hoặc cài cập nhật. Không có telemetry và không gửi nội dung tệp.

## Biện pháp

- Không follow symlink khi duyệt cây tệp.
- Giới hạn kích thước tệp trước khi đọc.
- Hủy quét tại ranh giới tệp bằng event thread-safe.
- Cập nhật bắt buộc HTTPS, SHA-256, schema validation và atomic replace.
- Quarantine dùng tên ngẫu nhiên, phần mở rộng không thực thi, permission hạn chế và integrity check trước restore.
- Settings/report JSON dùng atomic write.
- UI yêu cầu xác nhận trước restore overwrite hoặc xóa vĩnh viễn.

## Rủi ro còn lại

- Regex có false positive/false negative và nguy cơ performance nếu rule phát hành kém.
- SHA-256 manifest chưa cung cấp authenticity nếu update server bị chiếm hoàn toàn.
- Quarantine không mã hóa payload; người có quyền đọc user profile vẫn có thể truy cập bytes.
- Static scan không quan sát runtime behavior, memory-only malware hay dependency CVE.

## Khuyến nghị triển khai

Chạy với quyền user thường, không chạy administrator nếu không cần permission scan. Phát hành database qua CDN HTTPS riêng, thêm chữ ký Ed25519 cho manifest và dùng pipeline fuzz/regex-timeout trước khi production.

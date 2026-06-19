# Hướng dẫn sử dụng

## Bắt đầu

1. Mở **Quét mã độc**.
2. Chọn Quick, Smart hoặc Full.
3. Chọn thư mục dự án và nhấn **Bắt đầu quét**.
4. Theo dõi finding xuất hiện theo thời gian thực.
5. Chọn finding có tệp cụ thể và nhấn **Cách ly tệp đã chọn** nếu đã xác minh là nguy hiểm.

## Chọn chế độ

- Quick cho kiểm tra hằng ngày hoặc CI local.
- Smart là mặc định cho repository ứng dụng.
- Full dùng khi điều tra incident; có thể chậm do dependency/build output.

## Cách ly

Cách ly di chuyển tệp ra khỏi dự án, đổi phần mở rộng thành `.wgq`, giới hạn quyền truy cập và ghi SHA-256. Khi khôi phục, ứng dụng băm lại payload trước khi đưa về đường dẫn gốc. Nếu đường dẫn đã có tệp mới, người dùng phải xác nhận ghi đè.

## Exclusion

Thêm đường dẫn tương đối hoặc glob tại **Cài đặt → Loại trừ**, ví dụ:

```text
storage/cache/**
tests/fixtures/trusted-samples/**
C:/large/read-only-repository/vendor/**
```

Không loại trừ thư mục upload hoặc public nếu mục tiêu là tìm webshell.

## Xử lý false positive

Finding dangerous function không tự động đồng nghĩa mã độc. Kiểm tra nguồn dữ liệu đi vào hàm, vị trí tệp, commit tạo tệp và SHA-256. Dùng exclusion có phạm vi nhỏ cho fixture hoặc code sinh tự động; không whitelist toàn bộ repository.

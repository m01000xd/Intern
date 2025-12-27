Viết một virus lây file (File Infector) đáp ứng các tiêu chí sau:
Chỉ lây nhiễm file PE 32-bit (.exe, .dll) trong thư mục C:\test (để đảm bảo an toàn).
Không lây file .sys (driver hệ thống).
Khi một file PE bị nhiễm được chạy:
Đoạn mã lây lan phải được thực thi ngay.
Để chứng minh đoạn mã virus đã chạy, bắt buộc thực hiện in ra console (printf) hoặc hiển thị MessageBox với nội dung tuỳ ý (ví dụ: “Infected...”).
Không lây nhiễm cho chính nó hoặc các file đã bị lây từ trước.
Sau khi hiển thị thông báo, tiếp tục lây nhiễm các file PE chưa nhiễm khác trong thư mục C:\test.
Đảm bảo tại một thời điểm chỉ có duy nhất một tiến trình lây lan (dùng Mutex hoặc phương pháp khác).
File sau khi bị nhiễm vẫn hoạt động bình thường, không crash hoặc lỗi.

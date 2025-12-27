Thực hiện phân tích mẫu mã độc đơn giản, nhằm:

Xác định hành vi chính của phần mềm độc hại.
Trích xuất các chỉ số tấn công (IOCs).
Viết báo cáo kỹ thuật ngắn mô tả quá trình và kết quả phân tích.

Tệp mã độc được cung cấp:
Mỗi học viên nhận 1 tệp độc lập và 1 tệp chung "ramnit_7-Zip.zip" trong tệp bai_tap_6.zip.

Yêu cầu bài tập:
1. Thông tin tổng quan về tệp
Tên file, kích thước, hash (SHA256).
Kiểu file (PE32? Console? GUI?).
Có bị pack không? Nếu có, packer loại gì?

2. Phân tích tĩnh
Dùng Strings, PE-bear, CFF Explorer, IDA Pro hoặc Dependency Walker, ... để:

Tìm danh sách API được gọi.
Xác định các string khả nghi: URL, IP, file path, registry key,...
Nhận diện và phân tích các chức năng như:
Tạo/kết thúc process.
Tải file từ internet.
Ghi/đọc file hoặc registry.
Thiết lập autorun/persistence.
...

3. Phân tích động
Chạy trong môi trường VM giám sát bởi:

Procmon – theo dõi file/registry.
Process Explorer – theo dõi process/thread con.
TCPView hoặc Wireshark – phát hiện kết nối mạng.
IDA Debug, X64DBG

Trả lời:
File nào được tạo/ghi/xóa?
Có registry key nào bị chỉnh sửa?
Có kết nối đến domain/IP nào không?
Các hành vi khác của mã độc là gì?
Toàn bộ luồng hoạt động như thế nào?

4. Trích xuất IOC
Hash của file chính.
Tên/tệp hoặc đường dẫn được tạo.
Registry key bị thay đổi.
IP/domain liên quan (nếu có).
Chuỗi dấu hiệu (string/API đáng ngờ).

5. Kết luận kỹ thuật
Dự đoán loại malware (downloader, keylogger, trojan, ransomware, virus...).
Tác động hệ thống nếu malware được thực thi.

🔐 Lưu ý:
Chạy malware trong môi trường ảo cô lập.
Không tải malware lên các dịch vụ công cộng.

Nâng cao:
*Nếu đã hoàn thành bài cá nhân, có thể tiếp tục phân tích các mẫu còn lại
*Viết mã để xử lý mã độc ramnit

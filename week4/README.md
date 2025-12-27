Xây dựng chương trình quét virus (Antivirus Scanner):
Yêu cầu:
Nhận một thư mục đầu vào, duyệt toàn bộ các file PE trong đó.
Với mỗi file, phân tích cấu trúc PE để:
Phát hiện dấu hiệu nhiễm virus
Ghi log (file/console) các file bị nhiễm (tên file, entrypoint).
Bóc tách mã virus để trả về nguyên trạng file gốc. Lưu file sạch ra thư mục khác

Tạo log (file/console) báo cáo kết quả sau khi quét:
Tổng số file quét.
Số file bị nhiễm.
Số file bóc tách thành công.

Chương trình có thể viết bằng:
C/C++
ASM

Nâng cao:
Bổ sung GUI hỗ trợ các chức năng (chọn folder, file đầu vào/đầu ra, hiển thị kết quả...)

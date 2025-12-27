Yêu cầu bài tập:
Nhận diện packer
Sử dụng công cụ như PEiD, Detect It Easy (DIE), Exeinfo PE…
Xác định loại packer hoặc bảo vệ file đang dùng.

Môi trường an toàn
Thực hiện trên máy ảo (VMWare/VirtualBox).
Đảm bảo snapshot và tắt mạng để tránh lây nhiễm.

Unpack thủ công
Dùng OllyDbg hoặc x64dbg đặt breakpoint tại OEP (Original Entry Point).
Dump file từ bộ nhớ sau khi unpack xong.
Rebuild IAT (Import Address Table) bằng Scylla hoặc các công cụ tương tự.

Kiểm tra kết quả
File sau unpack phải chạy được.
Đảm bảo không còn lớp packer (kiểm tra lại bằng PEiD/DIE).

Báo cáo kết quả
Mô tả từng bước đã thực hiện (kèm screenshot).

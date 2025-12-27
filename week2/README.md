🧠 BÀI TẬP: PHÂN TÍCH FILE PE TRONG THƯ MỤC

🎯Mục tiêu
Lập trình bằng Assembly để duyệt thư mục, liệt kê và phân tích các file PE hợp lệ
(.exe/.dll). Hiển thị cấu trúc chi tiết của từng file PE.


✅Yêu cầu chức năng

Giao diện: Console hoặc GUI (Dialog).
Bước 1: Cho phép người dùng chọn thư mục trên đĩa.
Bước 2: Duyệt toàn bộ file trong thư mục, kiểm tra định dạng PE hợp lệ (MZ +
PE\0\0).
Bước 3: Phân tích chi tiết cấu trúc của từng file hợp lệ:

IMAGE_DOS_HEADER
IMAGE_NT_HEADERS

FileHeader,
OptionalHeader, DataDirectories, SectionHeader,
Export, Import, Resource, Relocation

🛡️Yêu cầu xử lý lỗi & edge case
Kiểm tra kỹ kết quả trả về của các API: FindFirstFile, CreateFile, ReadFile,
VirtualAlloc, v.v.
Các RVA/Size không vượt quá kích thước file
Không crash nếu file không chuẩn, thiếu dữ liệu.
Giải phóng đầy đủ bộ nhớ, handle, khi lỗi xảy ra.

🧠 BÀI TẬP: VIẾT PE LOADER

🎯 Mục tiêu
Mô phỏng quá trình load một file
PE như Windows PE Loader:

Đọc file PE từ đĩa.

Cấp phát vùng bộ nhớ theo
ImageBase/SizeOfImage.

Ánh xạ các section đúng địa chỉ
RVA.

Xử lý Entry Point: mô phỏng
chuyển quyền điều khiển.

Xử lý lỗi:
kiểm tra hợp lệ định dạng PE, cấu trúc header, section size, tránh crash khi dữ
liệu sai.

Ngôn ngữ:
+ asm (học cách mô phỏng ánh xạ bộ nhớ)
+ c/c++ (loader hoàn chỉnh có thể thực thi)

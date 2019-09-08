# HỆ THỐNG NHẬN DIỆN GÓI TIN
## Mô tả ứng dụng
Đây là một hệ thống phát hiện tấn công dựa trên việc đọc gói tin trực tiếp hoặc đọc file log sử dụng bộ dữ liệu học HTTP CSIC 2010. Sử dụng hai kỹ thuật để xây dựng mô hình phát hiện tấn công: Mô hình SVM và mô hình sử dụng Naives Bayes.
Chương trình có hai chức năng chính:
  - Đọc trực tiếp request từ pcap: Ở chế độ này, ứng dụng sẽ lọc các http request được gửi tới server, đem phân loại từng request, in kết quả lên màn hình đồng thời lưu ra file log riêng. Chế độ này có ưu điểm là đọc và phân loại tất cả gói tin gửi đến server mà không phân biệt web server nào. Tuy nhiên đối với mô hình mạng lớn, việc đọc tất cả các gói tin khiến cho server xử lý chậm chạp có thể gây crash ứng dụng
  - Đọc file pcap ngoại tuyến: Khi các gói tin gửi đến được tổng hợp và lưu dưới dạng file pcap, có thể dùng ứng dụng mở lên đọc các kết nối HTTP và phân loại.
  - Đọc trực tiếp file log từ webserver: Mỗi khi có kết nối đến web server được ghi vào file log, ứng dụng sẽ đọc các dòng mới này và đem đi phân loại request. Chế độ này có thể phân loại request thuộc về web server nào, ngoài ra giảm tải cho máy server vì chỉ đọc và phân tích những http request đã được lọc sẵn bởi web server.
  - Ngoài ra, ta có thể đọc lại các file log từ Apache, Nginx đã ghi sẵn cho quá trình phân loại và in kết quả.
  
  Với mô hình SVM, chương trình sẽ lấy các dữ liệu tại URL và Payload làm tiền đề để phân loại, vì vậy trước mắt chương trình chỉ có thể phân biệt các tấn công có tác động đến URL và Payload ví dụ như Command Injection, SQL Injection, XSS, Weak Session ID,…
## Cài đặt 
Chương trình chạy trên nền python2. Một số thư viện cần thiết:
  + Numpy
  + Scapy
  + Scikit-learn
  + Nltk
  + Gtk
  
  Chạy chương trình bằng file nids.py trong “Application/gui”
## Tham khảo
Many thanks to Phd. Diep Nguyen Ngoc and Deepak Paudel 

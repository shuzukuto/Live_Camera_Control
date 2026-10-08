# Đặc Tả Kỹ Thuật Dự Án (rules.md)

Tài liệu đặc tả kiến trúc, quy chuẩn giao diện và hành vi nghiệp vụ còn hiệu lực của Hệ thống Giám sát & Ghi hình Camera Tập trung (NVR/VMS Console).

---

## 1. Kiến Trúc Tổng Thể & Công Nghệ

- **Backend**: Python 3.10+ với FastAPI (Asynchronous ASGI framework), Uvicorn server, SlowAPI rate limiter.
- **Media Streaming Gateway**: `go2rtc` (Media server nhúng) cung cấp WebRTC WHEP (độ trễ < 200ms), MSE (fMP4), HLS và RTSP proxy.
- **Transcoding & Remuxing Engine**: FFmpeg 7.1 giải quyết sự cố phân mảnh video, tối ưu `faststart` container MP4.
- **Cơ Sở Dữ Liệu**: SQLite chạy chế độ Write-Ahead Logging (`WAL`), `synchronous = NORMAL`, `foreign_keys = ON` qua thư viện `aiosqlite`.
- **Bảo Mật Thông Tin Mật (Vault)**: Thuật toán mật mã AEAD chuẩn AES-256-GCM với 600,000 vòng lặp PBKDF2; khóa mã hóa lưu trữ cách ly trong thư mục `data/` không bao giờ gửi ra frontend.
- **Frontend**: Single Page Application (SPA) xây dựng theo chuẩn `ui-ux-pro-max`, `frontend-design`, `frontend-ui-engineering`, không cần phụ thuộc NodeJS khi chạy runtime; mount tĩnh tại `/` trong FastAPI.

---

## 2. Quản Lý Tài Khoản & Giao Thức Camera

### 2.1 Đám Mây EZVIZ Open Platform
- Đăng nhập qua AppKey / AppSecret hoặc Tài khoản/Mật khẩu.
- Tự động duy trì và gia hạn token truy cập (Access Token).
- Điều khiển PTZ đám mây, tự động trích xuất URL luồng HLS/RTSP/RTMP và đưa vào `go2rtc`.

### 2.2 Đám Mây Xiaomi Mi Home
- Hỗ trợ đăng nhập qua giao thức Xiaomi Passport (Email/SĐT/Mi ID + Mật khẩu).
- Hỗ trợ đầy đủ 6 phân vùng máy chủ đám mây:
  - `cn`: Mainland China (Trung Quốc Nội Địa)
  - `sg`: Singapore / Đông Nam Á
  - `us`: United States (Bắc Mỹ)
  - `de`: Germany / Châu Âu
  - `ru`: Russia (Nga)
  - `i2`: India (Ấn Độ)
- Tự động ký số HMAC-SHA256 cho các gói tin MIoT RPC.

### 2.3 Camera Generic IP & ONVIF
- Quét tìm kiếm tự động camera trên mạng LAN qua giao thức UDP Multicast WS-Discovery (`239.255.255.250:3702`).
- Trích xuất cấu hình SOAP `GetProfiles` và `GetStreamUri`.
- Che mờ (mask/redact) thông tin mật khẩu trong URL RTSP trước khi ghi log hoặc gửi tới giao diện người dùng.

---

## 3. Streaming Trực Tiếp 24/7 Không Giới Hạn (StreamKeeper Engine)

- **Vượt Hạn Chế Phiên Đám Mây**: Các hãng camera cloud (EZVIZ, Xiaomi) thường tự ngắt phiên sau 5-10 phút để tiết kiệm băng thông máy chủ. Daemon `StreamKeeper` kiểm tra trước hạn (proactive lead time 30s) và thực hiện gọi PATCH `/api/streams` tới `go2rtc` để hot-swap URL luồng mới mà không làm ngắt kết nối WebRTC của trình duyệt.
- **Ưu Tiên Mạng LAN**: Nếu camera có hỗ trợ luồng RTSP nội bộ trong cùng lớp mạng LAN, hệ thống tự động ưu tiên luồng nội bộ để giảm thiểu băng thông internet và triệt tiêu độ trễ.

---

## 4. Ghi Hình & Chụp Ảnh Thời Gian Thực (NVR Engine)

- **Ghi Hình Chống Lỗi fMP4**: Video được ghi ở định dạng fragmented MP4, đảm bảo tệp tin không bị lỗi kể cả khi server mất điện hoặc mất kết nối đột ngột.
- **Tối Ưu Phục Hồi (Startup Crash Sweep)**: Khi khởi động, hệ thống tự động quét và remux lại các file ghi hình dở dang về định dạng MP4 seekable (`faststart`).
- **Chính Sách Lưu Trữ FIFO (First-In, First-Out)**: Tự động dọn dẹp các bản ghi cũ nhất khi dung lượng ổ đĩa đạt ngưỡng cảnh báo hoặc dung lượng khả dụng dưới 20GB (bảo vệ tuyệt đối các tệp được người dùng bấm Khóa - Lock).
- **Snapshot Chất Lượng Cao**: Chụp khung hình gốc kèm watermark HUD thời gian thực và sinh ảnh thu nhỏ (thumbnail 320x180).

---

## 5. Chuẩn Hóa Nhật Ký Sự Kiện AI (AI Event Subsystem)

- **3 Lớp Sự Kiện Tiêu Chuẩn**:
  1. `Human`: Phát hiện người, nhận diện khuôn mặt, quét hình dáng người.
  2. `Movement`: Phát hiện chuyển động, cảm biến hồng ngoại PIR, vượt hàng rào ảo.
  3. `Abnormal Sound`: Phát hiện tiếng ồn lớn, tiếng khóc trẻ em, tiếng kính vỡ.
- **Tìm Kiếm & Lọc**: Ô tìm kiếm toàn trường (Universal Search) tìm kiếm trên tất cả các cột (`camera_name`, `camera_id`, `event_type`, `timestamp`, `metadata`).
- **Xuất Dữ Liệu 3 Chế Độ (Export Engine)**:
  1. **Template**: Header cột và 1 dòng mẫu định dạng CSV/XLSX.
  2. **Bảng Hiện Tại (Filtered)**: Toàn bộ dòng thỏa mãn bộ lọc tìm kiếm hiện tại.
  3. **Toàn Bộ (All)**: Mọi dòng trong bảng CSDL, không phân trang.
  - Tích hợp bộ lọc vô hiệu hóa tấn công CSV/XLSX Formula Injection (tự động prefix ký tự nháy đơn `'` cho các ô bắt đầu bằng `=`, `+`, `-`, `@`).
- **Phát Sóng Thời Gian Thực**: Kênh truyền kép WebSocket (`/api/ws/events`) và SSE (`/api/events/stream`) với gói tin heartbeat keep-alive mỗi 30 giây.

---

## 6. Quy Chuẩn Cổng Mạng & Giao Diện Người Dùng (Network & UI Architecture)

- **Cổng Mặc Định Ứng Dụng**: Sử dụng cổng **8090** (`http://localhost:8090/`) làm cổng mặc định thay cho 8000 để triệt tiêu hoàn toàn xung đột cổng với các hệ thống khác (ví dụ: `Hikvision_Monitoring_System` chạy trên cổng 8000). Cho phép linh hoạt cấu hình qua biến môi trường `PORT` hoặc tham số dòng lệnh `--port <số_cổng>`.
- **Cổng Media Gateway**: `1984` (go2rtc Web API & WHEP SDP exchange), `8554` (RTSP relay gateway), `8555` (WebRTC TCP/UDP streaming).
- **Hệ Thống Bảng Kiểu Độc Lập Khép Kín (Self-Contained Styling)**:
  - File `style.css` chứa toàn bộ utility classes (Flexbox, Grid, Modals, PTZ Joystick, Glassmorphism, Bảng dữ liệu, Toast, Scrollbars) giúp giao diện vận hành hoàn hảo 100% ngay cả khi máy chủ NAS hoạt động trong mạng LAN cô lập không có kết nối Internet.
  - Áp dụng cơ chế bảo vệ kích thước SVG kép (Dual SVG Bounding): bắt buộc thuộc tính HTML `width`/`height` trên từng thẻ `<svg>` và luật CSS `svg { display: inline-block; vertical-align: middle; flex-shrink: 0; max-width: 100%; max-height: 100%; }` kèm class `.w-* !important`, `.h-* !important` để ngăn ngừa triệt để lỗi phóng đại icon làm vỡ khung nhìn.


# Deep Remover by Duy Anh

Tool Windows chuyên dụng: **quét sâu + gỡ triệt để** mọi thành phần còn sót của phần mềm,
và **chặn / cho phép cài lại** qua cơ chế **IFEO**.

## Phần mềm hỗ trợ
360 Total Security · WPS Office · Avast Antivirus · Avast Free Antivirus ·
AVG AntiVirus · Norton AntiVirus · BKAV · McAfee

## Những gì tool dọn cho mỗi phần mềm
| Thành phần | Cách xử lý |
|---|---|
| Tiến trình chạy ngầm | `taskkill /F /T` |
| Dịch vụ hệ thống (service) | `sc stop` → `sc config start=disabled` → `sc delete` |
| Driver kernel tự bảo vệ | hạ `Start=disabled`, xóa, phần khóa → xóa khi reboot |
| Scheduled Tasks | quét theo từ khóa → `schtasks /delete` |
| Registry | export backup (thư mục `reg_backup`) rồi `reg delete` cả view 32/64 |
| File/thư mục rác | xóa cưỡng chế, file bị khóa → `MoveFileEx` xóa khi reboot |
| Trình gỡ của hãng | tự tìm trong Uninstall registry và chạy (tùy chọn) |

## Chặn cài lại (IFEO)
Ghi khóa `Image File Execution Options\<exe>` với `Debugger` trỏ tới `mshta` hiện
hộp thoại thông báo — khi ai đó chạy file cài, Windows chặn và báo. Bấm
**"Cho phép cài lại"** để gỡ chặn.

## Cách dùng
1. Chạy `DeepRemover.exe` (tự xin quyền Admin).
2. Tick phần mềm cần xử lý.
3. **QUÉT SÂU** để xem còn gì → **GỠ SẠCH** → (tùy chọn) **CHẶN CÀI LẠI**.

## Với AV có self-protection (Avast/AVG/Norton/McAfee/360/BKAV)
Khi self-protection đang bật, Windows **không cho** xóa lúc đang chạy. Quy trình chuẩn:
1. Chạy **GỠ SẠCH** lần 1 (đã hạ driver về disabled + xếp lịch xóa).
2. **Khởi động lại.**
3. Bấm **"Boot vào Safe Mode"** → khởi động lại → chạy **GỠ SẠCH** lần 2.
4. Bấm **"Tắt Safe Mode"** → khởi động lại bình thường.

## Dữ liệu
- `deep_remover.db` — SQLite lưu lịch sử thao tác (tự import `deep_remover_history.json` cũ, có backup).
- `config.json` — cấu hình sửa tay (thông điệp chặn, bật/tắt backup registry, tạo restore point...).
- `reg_backup\` — bản sao registry trước khi xóa (để khôi phục nếu cần).

## Build exe
Chạy `build.bat` (cần đã cài Python 3). Kết quả: `dist\DeepRemover.exe`.

## Lưu ý an toàn
- Nên để bật "Tạo điểm khôi phục trước khi gỡ".
- Tool backup registry trước khi xóa; muốn hoàn tác thì double-click file `.reg` trong `reg_backup`.
- Gỡ AV sẽ khiến máy mất bảo vệ — nhớ bật lại Windows Defender sau đó.

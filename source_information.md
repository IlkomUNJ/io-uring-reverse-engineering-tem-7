# Task 1: Information about io_uring source
List in this section source and headers of io_uring. For each of the C source/header, you must put description what's the prime responsibily of the source. Take notes, description of the source should be slightly technical like the example given. 

## Source
### advice.c
Menyimpan struktur io_madvice dan io_fadvice, keduanya memiliki atribut yang identik. Fungsi yang menggunakan io_madvice hanya akan dikompilasi jika build flag tertentu aktif, sedangkan io_fadvice selalu aktif. Perbedaan sebenarnya antara keduanya terlihat pada pemanggilan do_madvise (untuk madvice) dan vfs_fadvise (untuk fadvice).

### alloc_cache.c

Mengatur alokasi dan pengelolaan cache internal untuk struktur data io_uring. Bertanggung jawab terhadap efisiensi alokasi memori kernel melalui pengelompokan objek kecil (object cache).

### cancel.c

Berisi logika pembatalan operasi io_uring yang telah diajukan namun belum sempat diproses. Mencakup pemeriksaan status dan penghapusan aman dari queue internal.

### epoll.c

Mengimplementasikan dukungan untuk operasi epoll dalam io_uring. Berfungsi sebagai antarmuka antara event notification dan event loop io_uring.

### eventfd.c

Menangani interaksi antara io_uring dan eventfd. Memungkinkan proses untuk menunggu sinyal dari operasi I/O yang telah selesai melalui file descriptor.

### fdinfo.c

Mengisi informasi debug/profiling terkait file descriptor yang digunakan io_uring. Biasanya digunakan bersama /proc/[pid]/fdinfo.

### filetable.c

Mengelola pemetaan file descriptor terhadap file internal io_uring. File ini berperan dalam menyimpan, mereferensikan, dan membersihkan file yang telah diregister ke io_uring melalui op register. Menggunakan tabel internal untuk menghindari overhead lookup file berulang kali selama eksekusi I/O.

### fs.c

Mengatur operasi I/O terkait filesystem seperti read, write, dan sync. Bertanggung jawab menghubungkan syscall generik pengguna ke operasi kiocb (kernel I/O control block). Memastikan bahwa operasi yang dikirim user melalui io_uring memiliki konteks filesystem yang benar.

### futex.c

Mengimplementasikan operasi futex (fast userspace mutex) dalam konteks io_uring. Mungkinkan pengguna mengantri dan menunggu sinyal futex dari thread lain, serta mengatur wake-up. Digunakan untuk membangun sinkronisasi efisien antar thread di userspace menggunakan kernel secara asinkron.

### io_uring.c

File utama dari seluruh sistem io_uring. Mengatur inisialisasi, lifecycle, dan pengaturan ring buffer antara user dan kernel. Mengelola pengambilan dan penyelesaian request I/O, integrasi dengan SQ/CQ, dan dukungan submit multientry. Berisi juga berbagai syscall utama seperti io_uring_setup, io_uring_enter, dan io_uring_register.

### io_wq.c

Mengimplementasikan sistem worker thread dinamis (workqueue) io_wq. Worker ini digunakan untuk mengeksekusi operasi blocking secara terpisah dari context utama kernel thread. io_wq mengatur lifecycle thread, binding ke CPU, serta pemisahan antara unbounded dan bounded workers.

### kbuf.c

Menyediakan alokasi buffer kernel-side untuk operasi I/O yang melibatkan user pointers. Mencakup konversi dari user pointer ke buffer kernel internal dengan tetap menjaga keamanan memori dan performa.

### memmap.c

Mengelola pemetaan memory I/O dari userspace (seperti melalui mmap). Digunakan saat pengguna ingin berbagi buffer antara kernel dan userspace tanpa salinan data yang berlebihan.

### msg_ring.c

Mengatur komunikasi antar ring (io_uring) melalui pesan, memungkinkan sinkronisasi dan signal antar context berbeda (misal thread atau process). Mewakili sistem signaling berbasis ring message antar instance io_uring.

### napi.c

Integrasi io_uring dengan NAPI (New API) subsystem untuk network packet processing. Memungkinkan efisiensi tinggi dalam menangani I/O jaringan berbasis polling.

### net.c

Berisi dukungan untuk operasi I/O jaringan (recv, send, accept, connect) dalam io_uring. Menyesuaikan interface socket tradisional ke dalam model asinkron berbasis SQE.

### nop.c

Mengimplementasikan operasi dummy (no-operation). Umumnya digunakan untuk benchmarking, pengujian, atau sebagai placeholder dalam request submission.

### notif.c

Menangani pengiriman notifikasi dari kernel ke user secara asinkron. Biasanya digunakan untuk menyampaikan status atau kondisi tertentu yang bukan hasil langsung dari I/O.

### opdef.c

Berisi definisi statis dan metadata untuk semua jenis opcode (IORING_OP_*) yang didukung. Digunakan sebagai referensi saat decoding dan validasi SQE.

### openclose.c

Menyediakan implementasi asinkron untuk open, openat, dan close. Mengizinkan pembukaan dan penutupan file descriptor dalam io_uring tanpa blocking syscall.

### poll.c

Mengelola operasi polling (poll, select, atau epoll) dalam model io_uring. Mendukung pola event-driven I/O dan non-blocking menunggu readiness.

### register.c

Menangani proses registrasi berbagai resources ke io_uring: buffers, fds, file, personalities. Proses ini meningkatkan performa dengan menghindari repeated syscalls.

### rsrc.c

Mendukung manajemen resource lifecycle yang telah diregistrasi (seperti unregistasi buffer atau file). Terintegrasi erat dengan register.c untuk pemeliharaan data jangka panjang.

### rw.c

Mengimplementasikan operasi baca/tulis (read, write, pread, pwrite) ke file biasa maupun perangkat blok. Salah satu path I/O paling umum di io_uring.

### splice.c

Menangani operasi splice, yaitu transfer data antar file descriptor tanpa salinan user-kernel. Digunakan untuk efisiensi transfer data pipe, socket, atau file.

### sqpoll.c

Mengatur thread sqpoll, yaitu thread kernel yang secara aktif memantau Submission Queue tanpa syscall. Meningkatkan latensi rendah dengan membiarkan kernel langsung mengeksekusi SQE.

### statx.c

Implementasi operasi statx di io_uring untuk mengambil metadata file. Mendukung pengambilan data lebih detail daripada stat atau fstat.

### sync.c

Menangani sinkronisasi file atau filesystem (misalnya fsync, fdatasync) dalam bentuk asinkron. Berguna untuk memastikan durabilitas data pada penyimpanan disk.

### tctx.c

Mengelola struktur thread context io_uring, terutama ketika digunakan oleh thread pool. Menyediakan isolasi dan manajemen lifecycle untuk instance per-thread.

### timeout.c

Mengatur operasi timeout, termasuk penjadwalan waktu tunggu untuk request I/O atau event. Mendukung fungsi seperti IORING_OP_TIMEOUT dan IORING_OP_LINK_TIMEOUT.

### truncate.c

Mendukung operasi pemotongan ukuran file (truncate/ftruncate). Berguna untuk mengosongkan atau memotong file secara asinkron.

### uring_cmd.c

Menyediakan dukungan perintah khusus (uring_cmd) yang bisa dikustomisasi oleh driver atau subsistem lain. Fungsinya fleksibel dan digunakan dalam integrasi lanjutan (misalnya GPU driver).

### waitid.c

Mengimplementasikan operasi waitid secara non-blocking. Memungkinkan proses untuk menunggu status exit child process sebagai bagian dari event loop io_uring.

### xattr.c

Mendukung extended attributes (xattr) file seperti getxattr, setxattr. Memungkinkan akses metadata file secara fleksibel dan asinkron.

### zcrx.c

Digunakan untuk integrasi dengan Zero-Copy Receive (ZC RX). File ini menampung logika pengambilan data dari jaringan tanpa menyalin buffer.

## another source

## Headers

### advice.h

Mendeklarasikan spesifikasi fungsi untuk advice.c, termasuk fungsi io_madvise_prep dan io_fadvise_prep.

### alloc_cache.h

Menyediakan deklarasi fungsi dan struktur data untuk pengelolaan cache alokasi memori io_uring.

### cancel.h

Mendefinisikan fungsi dan struktur yang digunakan untuk pembatalan operasi di cancel.c.

### epoll.h

Menyediakan antarmuka fungsi yang digunakan modul lain untuk mengakses kemampuan epoll io_uring.

### eventfd.h

Mendeklarasikan fungsi pendukung untuk interaksi antara eventfd dan operasi io_uring.

### fdinfo.h

Mendeklarasikan fungsi dan struktur yang digunakan dalam fdinfo.c untuk menyusun informasi debugging/profiling ke dalam /proc/[pid]/fdinfo. Digunakan oleh subsystem procfs.

### filetable.h

Berisi deklarasi fungsi dan struktur untuk mengelola tabel file internal io_uring. Digunakan untuk lookup, refcounting, dan manajemen file descriptor yang telah diregistrasi.

### fs.h

Mendeklarasikan fungsi-fungsi yang menangani operasi filesystem generik (read, write, sync) yang dijalankan secara asinkron dalam io_uring.

### futex.h

Berisi definisi struktur dan fungsi untuk dukungan operasi futex asinkron. Digunakan oleh futex.c untuk melakukan antrian dan pembatalan wait/wake pada futex key.

### io-wq.h

Mendeklarasikan API untuk workqueue io_wq yang digunakan io_uring. Menyediakan pengaturan worker thread, pengelompokan work item, dan sinkronisasi eksekusi blocking ops.

### io_uring.h

Header utama io_uring. Berisi deklarasi struktur penting seperti io_ring_ctx, io_kiocb, dan fungsi inti pengelola lifecycle ring. Digunakan hampir di seluruh modul io_uring.

### memmap.h

Mendeklarasikan fungsi untuk pemetaan buffer dari user ke kernel. Memberi antarmuka untuk memeriksa, membuat, dan melepas mapping memory pengguna.

### kbuf.h

Berisi deklarasi fungsi untuk alokasi dan manajemen buffer kernel yang digunakan pada operasi berbasis user pointer. Mendukung verifikasi pointer dan validasi akses memori.

### msg_ring.h

Berisi deklarasi fungsi untuk dukungan message ring antar instance io_uring. Digunakan untuk signalling dan sinkronisasi antara context kernel yang berbeda.

### napi.h

Mendeklarasikan interface antara io_uring dan subsystem NAPI untuk network polling. Digunakan untuk penjadwalan ulang dan integrasi packet receive dengan event I/O.

### net.h

Header untuk operasi I/O jaringan io_uring. Mendeklarasikan fungsi-fungsi seperti io_recv_prep, io_send_prep, dan berbagai bentuk socket handling.

### nop.h

Berisi deklarasi fungsi io_nop_prep dan io_nop, yang digunakan untuk operasi dummy/no-op dalam ring. Biasanya digunakan untuk testing atau pengisi tempat.

### notif.h

Mendefinisikan API untuk pengiriman notifikasi dari kernel ke userspace dalam bentuk operasi I/O tersendiri. Digunakan saat kernel ingin menyampaikan event tertentu secara eksplisit.

### opdef.h

Berisi daftar definisi opcode io_uring dan metadata deskriptifnya seperti flags, validasi, dan struktur pendukung. Digunakan oleh sistem dispatch.

### openclose.h

Mendeklarasikan operasi open/close non-blocking untuk file descriptor yang dikirim melalui io_uring.

### poll.h

Berisi deklarasi operasi polling yang terintegrasi dengan io_uring, termasuk poll_prep, poll_arm, dan poll_cancel.

### refs.h

Mendefinisikan struktur dan fungsi untuk reference counting objek internal io_uring, termasuk lifecycle manajemen yang aman dan atomik.

### register.h

Mendeklarasikan fungsi untuk proses registrasi buffer, file, dan resource lainnya yang dipakai oleh io_uring. Digunakan bersama rsrc.h.

### rsrc.h

Berisi struktur internal untuk menyimpan resource yang telah diregistrasi (fd, buffer). Digunakan oleh register/unregister dan dipanggil saat context dibersihkan.

### rw.h

Mendeklarasikan operasi baca/tulis asinkron io_uring (pread, pwrite) termasuk persiapan dan eksekusinya.

### slist.h

Berisi implementasi lockless single-linked list untuk antrian internal io_uring. Digunakan untuk keperluan performa tinggi pada penjadwalan task.

### splice.h

Berisi deklarasi fungsi untuk mendukung operasi splice antar file descriptor yang ditangani io_uring.

### sqpoll.h

Mendeklarasikan fungsi dan struktur untuk thread polling submission queue. Digunakan jika opsi SQPOLL aktif saat setup.

### statx.h

Mendeklarasikan fungsi untuk mengambil metadata file (statx) dalam bentuk asinkron di io_uring.

### sync.h

Berisi deklarasi fungsi fsync, fdatasync, dan sinkronisasi lainnya. Digunakan untuk menjamin durabilitas data I/O yang telah dilakukan.

### tctx.h

Mendeklarasikan struktur io_uring_task dan io_uring_tctx, yang merepresentasikan state per-thread. Digunakan untuk mendukung multithreading.

### timeout.h

Berisi definisi dan fungsi terkait operasi timeout dan timeout chaining. Termasuk pembatalan dan pengelolaan event waktu dalam queue.

### truncate.h

Mendeklarasikan operasi truncate/ftruncate pada file descriptor. Digunakan dalam operasi I/O file yang memerlukan pemangkasan panjang file.

### uring_cmd.h

Berisi struktur dan fungsi untuk custom uring commands (uring_cmd), memungkinkan integrasi kernel driver terhadap sistem I/O.

### waitid.h

Mendeklarasikan fungsi io_waitid yang digunakan untuk menunggu status child process melalui antarmuka asinkron.

### xattr.h

Berisi deklarasi untuk operasi extended attribute (xattr), mendukung fungsi getxattr, setxattr, dan lainnya dalam io_uring.

### zcrx.h

Mendeklarasikan interface Zero-Copy Receive untuk pengambilan data dari jaringan tanpa overhead salinan buffer.
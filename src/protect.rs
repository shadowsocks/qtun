use std::io;
use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;
use std::os::unix::io::RawFd;
use std::os::unix::net::UnixStream;
use std::time::Duration;

/// Protect a socket fd by sending it to the Android VPN service via
/// a Unix domain socket at "protect_path".
///
/// The protocol:
/// 1. Connect to abstract Unix domain socket "protect_path"
/// 2. Send the fd as SCM_RIGHTS ancillary data with a 1-byte dummy payload
/// 3. Read a 1-byte acknowledgment from the VPN service
///
/// This mirrors the behavior of v2ray-plugin's utils_android.go.
pub fn protect(fd: RawFd) -> io::Result<()> {
    let stream = UnixStream::connect("protect_path")?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;

    send_fd(&stream, fd)?;

    // Wait for 1-byte acknowledgment
    let mut buf = [0u8; 1];
    (&stream).read_exact(&mut buf)?;

    Ok(())
}

/// Send a file descriptor over a Unix domain socket using SCM_RIGHTS.
fn send_fd(stream: &UnixStream, fd: RawFd) -> io::Result<()> {
    use libc::{
        c_void, cmsghdr, iovec, msghdr, sendmsg, CMSG_DATA, CMSG_FIRSTHDR, CMSG_LEN, CMSG_SPACE,
        SCM_RIGHTS, SOL_SOCKET,
    };
    use std::mem;
    use std::ptr;

    let dummy: [u8; 1] = [b'!'];

    let mut iov = iovec {
        iov_base: dummy.as_ptr() as *mut c_void,
        iov_len: 1,
    };

    // Allocate space for the control message containing one fd
    let cmsg_space = unsafe { CMSG_SPACE(mem::size_of::<RawFd>() as u32) } as usize;
    let mut cmsg_buf = vec![0u8; cmsg_space];

    let mut msg: msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut c_void;
    msg.msg_controllen = cmsg_space as _;

    let cmsg: &mut cmsghdr = unsafe { &mut *CMSG_FIRSTHDR(&msg) };
    cmsg.cmsg_level = SOL_SOCKET;
    cmsg.cmsg_type = SCM_RIGHTS;
    cmsg.cmsg_len = unsafe { CMSG_LEN(mem::size_of::<RawFd>() as u32) } as _;

    unsafe {
        ptr::copy_nonoverlapping(
            &fd as *const RawFd as *const u8,
            CMSG_DATA(cmsg),
            mem::size_of::<RawFd>(),
        );
    }

    let result = unsafe { sendmsg(stream.as_raw_fd(), &msg, 0) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

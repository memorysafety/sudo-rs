/* automatically generated by rust-bindgen 0.66.1, minified by cargo-minify, edited to be portable */

// NOTE: the tests below test the assumptions about the padding that a C compiler will use on the
// above structs; if these assumptions are incorrect, the tests will fail, but most likely the
// code will still be correct.

pub const PAM_SUCCESS: libc::c_int = 0;
pub const PAM_OPEN_ERR: libc::c_int = 1;
pub const PAM_SYMBOL_ERR: libc::c_int = 2;
pub const PAM_SERVICE_ERR: libc::c_int = 3;
pub const PAM_SYSTEM_ERR: libc::c_int = 4;
pub const PAM_BUF_ERR: libc::c_int = 5;
pub const PAM_PERM_DENIED: libc::c_int = 6;
pub const PAM_AUTH_ERR: libc::c_int = 7;
pub const PAM_CRED_INSUFFICIENT: libc::c_int = 8;
pub const PAM_AUTHINFO_UNAVAIL: libc::c_int = 9;
pub const PAM_USER_UNKNOWN: libc::c_int = 10;
pub const PAM_MAXTRIES: libc::c_int = 11;
pub const PAM_NEW_AUTHTOK_REQD: libc::c_int = 12;
pub const PAM_ACCT_EXPIRED: libc::c_int = 13;
pub const PAM_SESSION_ERR: libc::c_int = 14;
pub const PAM_CRED_UNAVAIL: libc::c_int = 15;
pub const PAM_CRED_EXPIRED: libc::c_int = 16;
pub const PAM_CRED_ERR: libc::c_int = 17;
pub const PAM_NO_MODULE_DATA: libc::c_int = 18;
pub const PAM_CONV_ERR: libc::c_int = 19;
pub const PAM_AUTHTOK_ERR: libc::c_int = 20;
pub const PAM_AUTHTOK_RECOVERY_ERR: libc::c_int = 21;
pub const PAM_AUTHTOK_LOCK_BUSY: libc::c_int = 22;
pub const PAM_AUTHTOK_DISABLE_AGING: libc::c_int = 23;
pub const PAM_TRY_AGAIN: libc::c_int = 24;
pub const PAM_IGNORE: libc::c_int = 25;
pub const PAM_ABORT: libc::c_int = 26;
pub const PAM_AUTHTOK_EXPIRED: libc::c_int = 27;
pub const PAM_MODULE_UNKNOWN: libc::c_int = 28;
pub const PAM_BAD_ITEM: libc::c_int = 29;
pub const PAM_SILENT: libc::c_int = 32768;
pub const PAM_DISALLOW_NULL_AUTHTOK: libc::c_int = 1;
pub const PAM_REINITIALIZE_CRED: libc::c_int = 8;
pub const PAM_CHANGE_EXPIRED_AUTHTOK: libc::c_int = 32;
pub const PAM_USER: libc::c_int = 2;
pub const PAM_TTY: libc::c_int = 3;
pub const PAM_RUSER: libc::c_int = 8;
pub const PAM_DATA_SILENT: libc::c_int = 1073741824;
pub const PAM_PROMPT_ECHO_OFF: libc::c_int = 1;
pub const PAM_PROMPT_ECHO_ON: libc::c_int = 2;
pub const PAM_ERROR_MSG: libc::c_int = 3;
pub const PAM_TEXT_INFO: libc::c_int = 4;
pub const PAM_MAX_RESP_SIZE: libc::c_int = 512;
pub type pam_handle_t = libc::c_void;
extern "C" {
    pub fn pam_set_item(
        pamh: *mut pam_handle_t,
        item_type: libc::c_int,
        item: *const libc::c_void,
    ) -> libc::c_int;
}
extern "C" {
    pub fn pam_get_item(
        pamh: *const pam_handle_t,
        item_type: libc::c_int,
        item: *mut *const libc::c_void,
    ) -> libc::c_int;
}
extern "C" {
    pub fn pam_strerror(pamh: *mut pam_handle_t, errnum: libc::c_int) -> *const libc::c_char;
}
extern "C" {
    pub fn pam_getenvlist(pamh: *mut pam_handle_t) -> *mut *mut libc::c_char;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct pam_message {
    pub msg_style: libc::c_int,
    pub msg: *const libc::c_char,
}
#[test]
fn bindgen_test_layout_pam_message() {
    const UNINIT: ::std::mem::MaybeUninit<pam_message> = ::std::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::std::mem::align_of::<pam_message>(),
        ::std::mem::align_of::<*mut libc::c_void>(),
        concat!("Alignment of ", stringify!(pam_message))
    );
    let mut offset: usize = 0;
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).msg_style) as usize - ptr as usize },
        offset,
        concat!(
            "Offset of field: ",
            stringify!(pam_message),
            "::",
            stringify!(msg_style)
        )
    );
    offset = aligned_offset::<*const libc::c_char>(offset + ::std::mem::size_of::<libc::c_int>());
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).msg) as usize - ptr as usize },
        offset,
        concat!(
            "Offset of field: ",
            stringify!(pam_message),
            "::",
            stringify!(msg)
        )
    );
    offset = aligned_offset::<*const libc::c_void>(
        offset + ::std::mem::size_of::<*const libc::c_char>(),
    );
    assert_eq!(
        ::std::mem::size_of::<pam_message>(),
        offset,
        concat!("Size of: ", stringify!(pam_message))
    );
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct pam_response {
    pub resp: *mut libc::c_char,
    pub resp_retcode: libc::c_int,
}
#[test]
fn bindgen_test_layout_pam_response() {
    const UNINIT: ::std::mem::MaybeUninit<pam_response> = ::std::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::std::mem::align_of::<pam_response>(),
        ::std::mem::align_of::<*mut libc::c_char>(),
        concat!("Alignment of ", stringify!(pam_response))
    );
    let mut offset: usize = 0;
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).resp) as usize - ptr as usize },
        offset,
        concat!(
            "Offset of field: ",
            stringify!(pam_response),
            "::",
            stringify!(resp)
        )
    );
    offset = aligned_offset::<libc::c_int>(offset + ::std::mem::size_of::<*mut libc::c_char>());
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).resp_retcode) as usize - ptr as usize },
        offset,
        concat!(
            "Offset of field: ",
            stringify!(pam_response),
            "::",
            stringify!(resp_retcode)
        )
    );
    offset = aligned_offset::<*mut libc::c_void>(offset + ::std::mem::size_of::<libc::c_int>());
    assert_eq!(
        ::std::mem::size_of::<pam_response>(),
        offset,
        concat!("Size of: ", stringify!(pam_response))
    );
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct pam_conv {
    pub conv: ::std::option::Option<
        unsafe extern "C" fn(
            num_msg: libc::c_int,
            msg: *mut *const pam_message,
            resp: *mut *mut pam_response,
            appdata_ptr: *mut libc::c_void,
        ) -> libc::c_int,
    >,
    pub appdata_ptr: *mut libc::c_void,
}
#[test]
fn bindgen_test_layout_pam_conv() {
    const UNINIT: ::std::mem::MaybeUninit<pam_conv> = ::std::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::std::mem::align_of::<pam_conv>(),
        ::std::mem::align_of::<*mut libc::c_void>(),
        concat!("Alignment of ", stringify!(pam_conv))
    );
    let mut offset: usize = 0;
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).conv) as usize - ptr as usize },
        offset,
        concat!(
            "Offset of field: ",
            stringify!(pam_conv),
            "::",
            stringify!(conv)
        )
    );
    offset =
        aligned_offset::<*mut libc::c_void>(offset + ::std::mem::size_of::<*mut libc::c_void>());
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).appdata_ptr) as usize - ptr as usize },
        offset,
        concat!(
            "Offset of field: ",
            stringify!(pam_conv),
            "::",
            stringify!(appdata_ptr)
        )
    );
    offset =
        aligned_offset::<*mut libc::c_void>(offset + ::std::mem::size_of::<*mut libc::c_void>());
    assert_eq!(
        ::std::mem::size_of::<pam_conv>(),
        offset,
        concat!("Size of: ", stringify!(pam_conv))
    );
}
extern "C" {
    pub fn pam_start(
        service_name: *const libc::c_char,
        user: *const libc::c_char,
        pam_conversation: *const pam_conv,
        pamh: *mut *mut pam_handle_t,
    ) -> libc::c_int;
}
extern "C" {
    pub fn pam_end(pamh: *mut pam_handle_t, pam_status: libc::c_int) -> libc::c_int;
}
extern "C" {
    pub fn pam_authenticate(pamh: *mut pam_handle_t, flags: libc::c_int) -> libc::c_int;
}
extern "C" {
    pub fn pam_setcred(pamh: *mut pam_handle_t, flags: libc::c_int) -> libc::c_int;
}
extern "C" {
    pub fn pam_acct_mgmt(pamh: *mut pam_handle_t, flags: libc::c_int) -> libc::c_int;
}
extern "C" {
    pub fn pam_open_session(pamh: *mut pam_handle_t, flags: libc::c_int) -> libc::c_int;
}
extern "C" {
    pub fn pam_close_session(pamh: *mut pam_handle_t, flags: libc::c_int) -> libc::c_int;
}
extern "C" {
    pub fn pam_chauthtok(pamh: *mut pam_handle_t, flags: libc::c_int) -> libc::c_int;
}
pub type __uid_t = libc::c_uint;
pub type __gid_t = libc::c_uint;
pub type gid_t = __gid_t;
pub type uid_t = __uid_t;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct passwd {
    pub pw_name: *mut libc::c_char,
    pub pw_passwd: *mut libc::c_char,
    pub pw_uid: __uid_t,
    pub pw_gid: __gid_t,
    pub pw_gecos: *mut libc::c_char,
    pub pw_dir: *mut libc::c_char,
    pub pw_shell: *mut libc::c_char,
}
#[test]
fn bindgen_test_layout_passwd() {
    const UNINIT: ::std::mem::MaybeUninit<passwd> = ::std::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::std::mem::align_of::<passwd>(),
        ::std::mem::align_of::<*mut libc::c_char>(),
        concat!("Alignment of ", stringify!(passwd))
    );
    let mut offset: usize = 0;
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).pw_name) as usize - ptr as usize },
        offset,
        concat!(
            "Offset of field: ",
            stringify!(passwd),
            "::",
            stringify!(pw_name)
        )
    );
    offset =
        aligned_offset::<*mut libc::c_char>(offset + ::std::mem::size_of::<*mut libc::c_char>());
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).pw_passwd) as usize - ptr as usize },
        offset,
        concat!(
            "Offset of field: ",
            stringify!(passwd),
            "::",
            stringify!(pw_passwd)
        )
    );
    offset = aligned_offset::<__uid_t>(offset + ::std::mem::size_of::<*mut libc::c_char>());
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).pw_uid) as usize - ptr as usize },
        offset,
        concat!(
            "Offset of field: ",
            stringify!(passwd),
            "::",
            stringify!(pw_uid)
        )
    );
    offset = aligned_offset::<__gid_t>(offset + ::std::mem::size_of::<__uid_t>());
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).pw_gid) as usize - ptr as usize },
        offset,
        concat!(
            "Offset of field: ",
            stringify!(passwd),
            "::",
            stringify!(pw_gid)
        )
    );
    offset = aligned_offset::<*mut libc::c_char>(offset + ::std::mem::size_of::<__gid_t>());
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).pw_gecos) as usize - ptr as usize },
        offset,
        concat!(
            "Offset of field: ",
            stringify!(passwd),
            "::",
            stringify!(pw_gecos)
        )
    );
    offset =
        aligned_offset::<*mut libc::c_char>(offset + ::std::mem::size_of::<*mut libc::c_char>());
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).pw_dir) as usize - ptr as usize },
        offset,
        concat!(
            "Offset of field: ",
            stringify!(passwd),
            "::",
            stringify!(pw_dir)
        )
    );
    offset =
        aligned_offset::<*mut libc::c_char>(offset + ::std::mem::size_of::<*mut libc::c_char>());
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).pw_shell) as usize - ptr as usize },
        offset,
        concat!(
            "Offset of field: ",
            stringify!(passwd),
            "::",
            stringify!(pw_shell)
        )
    );
    offset =
        aligned_offset::<*mut libc::c_void>(offset + ::std::mem::size_of::<*mut libc::c_char>());
    assert_eq!(
        ::std::mem::size_of::<passwd>(),
        offset,
        concat!("Size of: ", stringify!(passwd))
    );
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct group {
    pub gr_name: *mut libc::c_char,
    pub gr_passwd: *mut libc::c_char,
    pub gr_gid: __gid_t,
    pub gr_mem: *mut *mut libc::c_char,
}
#[test]
fn bindgen_test_layout_group() {
    const UNINIT: ::std::mem::MaybeUninit<group> = ::std::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::std::mem::align_of::<group>(),
        ::std::mem::align_of::<*mut libc::c_char>(),
        concat!("Alignment of ", stringify!(group))
    );
    let mut offset: usize = 0;
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).gr_name) as usize - ptr as usize },
        offset,
        concat!(
            "Offset of field: ",
            stringify!(group),
            "::",
            stringify!(gr_name)
        )
    );
    offset =
        aligned_offset::<*mut libc::c_char>(offset + ::std::mem::size_of::<*mut libc::c_char>());
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).gr_passwd) as usize - ptr as usize },
        offset,
        concat!(
            "Offset of field: ",
            stringify!(group),
            "::",
            stringify!(gr_passwd)
        )
    );
    offset = aligned_offset::<__gid_t>(offset + ::std::mem::size_of::<*mut libc::c_char>());
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).gr_gid) as usize - ptr as usize },
        offset,
        concat!(
            "Offset of field: ",
            stringify!(group),
            "::",
            stringify!(gr_gid)
        )
    );
    offset = aligned_offset::<*mut libc::c_char>(offset + ::std::mem::size_of::<__gid_t>());
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).gr_mem) as usize - ptr as usize },
        offset,
        concat!(
            "Offset of field: ",
            stringify!(group),
            "::",
            stringify!(gr_mem)
        )
    );
    offset =
        aligned_offset::<*mut libc::c_void>(offset + ::std::mem::size_of::<*mut libc::c_char>());
    assert_eq!(
        ::std::mem::size_of::<group>(),
        offset,
        concat!("Size of: ", stringify!(group))
    );
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct spwd {
    pub sp_namp: *mut libc::c_char,
    pub sp_pwdp: *mut libc::c_char,
    pub sp_lstchg: libc::c_long,
    pub sp_min: libc::c_long,
    pub sp_max: libc::c_long,
    pub sp_warn: libc::c_long,
    pub sp_inact: libc::c_long,
    pub sp_expire: libc::c_long,
    pub sp_flag: libc::c_ulong,
}
#[test]
fn bindgen_test_layout_spwd() {
    const UNINIT: ::std::mem::MaybeUninit<spwd> = ::std::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::std::mem::align_of::<spwd>(),
        ::std::mem::align_of::<*mut libc::c_char>(),
        concat!("Alignment of ", stringify!(spwd))
    );
    let mut offset: usize = 0;
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).sp_namp) as usize - ptr as usize },
        offset,
        concat!(
            "Offset of field: ",
            stringify!(spwd),
            "::",
            stringify!(sp_namp)
        )
    );
    offset =
        aligned_offset::<*mut libc::c_char>(offset + ::std::mem::size_of::<*mut libc::c_char>());
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).sp_pwdp) as usize - ptr as usize },
        offset,
        concat!(
            "Offset of field: ",
            stringify!(spwd),
            "::",
            stringify!(sp_pwdp)
        )
    );
    offset = aligned_offset::<libc::c_long>(offset + ::std::mem::size_of::<*mut libc::c_char>());
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).sp_lstchg) as usize - ptr as usize },
        offset,
        concat!(
            "Offset of field: ",
            stringify!(spwd),
            "::",
            stringify!(sp_lstchg)
        )
    );
    offset = aligned_offset::<libc::c_long>(offset + ::std::mem::size_of::<libc::c_long>());
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).sp_min) as usize - ptr as usize },
        offset,
        concat!(
            "Offset of field: ",
            stringify!(spwd),
            "::",
            stringify!(sp_min)
        )
    );
    offset = aligned_offset::<libc::c_long>(offset + ::std::mem::size_of::<libc::c_long>());
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).sp_max) as usize - ptr as usize },
        offset,
        concat!(
            "Offset of field: ",
            stringify!(spwd),
            "::",
            stringify!(sp_max)
        )
    );
    offset = aligned_offset::<libc::c_long>(offset + ::std::mem::size_of::<libc::c_long>());
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).sp_warn) as usize - ptr as usize },
        offset,
        concat!(
            "Offset of field: ",
            stringify!(spwd),
            "::",
            stringify!(sp_warn)
        )
    );
    offset = aligned_offset::<libc::c_long>(offset + ::std::mem::size_of::<libc::c_long>());
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).sp_inact) as usize - ptr as usize },
        offset,
        concat!(
            "Offset of field: ",
            stringify!(spwd),
            "::",
            stringify!(sp_inact)
        )
    );
    offset = aligned_offset::<libc::c_long>(offset + ::std::mem::size_of::<libc::c_long>());
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).sp_expire) as usize - ptr as usize },
        offset,
        concat!(
            "Offset of field: ",
            stringify!(spwd),
            "::",
            stringify!(sp_expire)
        )
    );
    offset = aligned_offset::<libc::c_long>(offset + ::std::mem::size_of::<libc::c_long>());
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).sp_flag) as usize - ptr as usize },
        offset,
        concat!(
            "Offset of field: ",
            stringify!(spwd),
            "::",
            stringify!(sp_flag)
        )
    );
    offset = aligned_offset::<*mut libc::c_void>(offset + ::std::mem::size_of::<libc::c_long>());
    assert_eq!(
        ::std::mem::size_of::<spwd>(),
        offset,
        concat!("Size of: ", stringify!(spwd))
    );
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct pam_modutil_privs {
    pub grplist: *mut gid_t,
    pub number_of_groups: libc::c_int,
    pub allocated: libc::c_int,
    pub old_gid: gid_t,
    pub old_uid: uid_t,
    pub is_dropped: libc::c_int,
}
#[test]
fn bindgen_test_layout_pam_modutil_privs() {
    const UNINIT: ::std::mem::MaybeUninit<pam_modutil_privs> = ::std::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::std::mem::align_of::<pam_modutil_privs>(),
        ::std::mem::align_of::<*mut gid_t>(),
        concat!("Alignment of ", stringify!(pam_modutil_privs))
    );
    let mut offset: usize = 0;
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).grplist) as usize - ptr as usize },
        offset,
        concat!(
            "Offset of field: ",
            stringify!(pam_modutil_privs),
            "::",
            stringify!(grplist)
        )
    );
    offset = aligned_offset::<libc::c_int>(offset + ::std::mem::size_of::<*mut gid_t>());
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).number_of_groups) as usize - ptr as usize },
        offset,
        concat!(
            "Offset of field: ",
            stringify!(pam_modutil_privs),
            "::",
            stringify!(number_of_groups)
        )
    );
    offset = aligned_offset::<libc::c_int>(offset + ::std::mem::size_of::<libc::c_int>());
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).allocated) as usize - ptr as usize },
        offset,
        concat!(
            "Offset of field: ",
            stringify!(pam_modutil_privs),
            "::",
            stringify!(allocated)
        )
    );
    offset = aligned_offset::<__gid_t>(offset + ::std::mem::size_of::<libc::c_int>());
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).old_gid) as usize - ptr as usize },
        offset,
        concat!(
            "Offset of field: ",
            stringify!(pam_modutil_privs),
            "::",
            stringify!(old_gid)
        )
    );
    offset = aligned_offset::<__uid_t>(offset + ::std::mem::size_of::<__gid_t>());
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).old_uid) as usize - ptr as usize },
        offset,
        concat!(
            "Offset of field: ",
            stringify!(pam_modutil_privs),
            "::",
            stringify!(old_uid)
        )
    );
    offset = aligned_offset::<libc::c_int>(offset + ::std::mem::size_of::<__uid_t>());
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).is_dropped) as usize - ptr as usize },
        offset,
        concat!(
            "Offset of field: ",
            stringify!(pam_modutil_privs),
            "::",
            stringify!(is_dropped)
        )
    );
    offset = aligned_offset::<*mut libc::c_void>(offset + ::std::mem::size_of::<libc::c_int>());
    assert_eq!(
        ::std::mem::size_of::<pam_modutil_privs>(),
        offset,
        concat!("Size of: ", stringify!(pam_modutil_privs))
    );
}

#[cfg(test)]
fn aligned_offset<T>(offset: usize) -> usize {
    let offset = offset as isize;
    let alignment = ::std::mem::align_of::<T>() as isize;
    (offset + (-offset).rem_euclid(alignment)) as usize
}

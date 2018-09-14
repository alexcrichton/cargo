use std::fs;
use std::io::{self, Read};
use std::net::TcpListener;
use std::process::{Child, Stdio, Command};
use std::thread;
use std::time::Duration;

use support::project;

trait NewProcessGroup {
    fn new_process_group(&mut self) -> &mut Self;
}

#[cfg(unix)]
impl NewProcessGroup for Command {
    fn new_process_group(&mut self) -> &mut Self {
        use std::os::unix::prelude::*;
        self.before_exec(|| {
            unsafe { ::libc::setsid(); }
            Ok(())
        });
        self
    }
}

#[cfg(windows)]
impl NewProcessGroup for Command {
    fn new_process_group(&mut self) -> &mut Self {
        use std::os::windows::process::*;
        use winapi::um::winbase::CREATE_NEW_PROCESS_GROUP;

        self.creation_flags(CREATE_NEW_PROCESS_GROUP)
    }
}

#[cfg(unix)]
fn enabled() -> bool {
    true
}

// On Windows support for these tests is only enabled through the usage of job
// objects. Support for nested job objects, however, was added in recent-ish
// versions of Windows, so this test may not always be able to succeed.
//
// As a result, we try to add ourselves to a job object here
// can succeed or not.
#[cfg(windows)]
fn enabled() -> bool {
    use winapi::um::{handleapi, jobapi, jobapi2, processthreadsapi};

    unsafe {
        // If we're not currently in a job, then we can definitely run these
        // tests.
        let me = processthreadsapi::GetCurrentProcess();
        let mut ret = 0;
        let r = jobapi::IsProcessInJob(me, 0 as *mut _, &mut ret);
        assert_ne!(r, 0);
        if ret == ::winapi::shared::minwindef::FALSE {
            return true;
        }

        // If we are in a job, then we can run these tests if we can be added to
        // a nested job (as we're going to create a nested job no matter what as
        // part of these tests.
        //
        // If we can't be added to a nested job, then these tests will
        // definitely fail, and there's not much we can do about that.
        let job = jobapi2::CreateJobObjectW(0 as *mut _, 0 as *const _);
        assert!(!job.is_null());
        let r = jobapi2::AssignProcessToJobObject(job, me);
        handleapi::CloseHandle(job);
        r != 0
    }
}

// This is a test emulating similar behavior on Windows and Unix for when ctrl-c
// is hit at a shell. In both cases Cargo should tear down all processes
// involved.
//
// On Unix this basically happens by default because all shell processes are in
// their own process group and ctrl-c at a shell sends the signal to the entire
// process group. To that end we just make sure that on unix we're in a new
// process group and then send a signal to the whole process group.
//
// On Windows though this doesn't always happen by default. If you're running
// an "official" windows shell then `GenerateConsoleCtrlEvent` is probably used
// by `cmd.exe`, which means (according to its docs) all processes get an event
// notification with the default handler being to die. If you're in the msys
// shell, however, then only the foreground process is killed (via
// `TerminateProcess` it's thought). This means that Cargo uses job objects on
// Windows to ensure that everything is torn down on ctrl-c, whether or not
// we're in msys or cmd.exe.
#[test]
fn ctrl_c_kills_everyone() {
    if !enabled() {
        return;
    }

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let p = project()
        .file(
            "Cargo.toml",
            r#"
                [package]
                name = "foo"
                version = "0.0.1"
                authors = []
                build = "build.rs"
            "#,
        ).file("src/lib.rs", "")
        .file(
            "build.rs",
            &format!(
                r#"
                    use std::net::TcpStream;
                    use std::io::Read;

                    fn main() {{
                        let mut socket = TcpStream::connect("{}").unwrap();
                        let _ = socket.read(&mut [0; 10]);
                        panic!("that read should never return");
                    }}
                "#,
                addr
            ),
        ).build();

    let mut cargo = p.cargo("build").build_command();
    cargo
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .new_process_group();
    let mut child = cargo.spawn().unwrap();

    let mut sock = listener.accept().unwrap().0;
    ctrl_c(&mut child);

    assert!(!child.wait().unwrap().success());
    match sock.read(&mut [0; 10]) {
        Ok(n) => assert_eq!(n, 0),
        Err(e) => assert_eq!(e.kind(), io::ErrorKind::ConnectionReset),
    }

    // Ok so what we just did was spawn cargo that spawned a build script, then
    // we killed cargo in hopes of it killing the build script as well. If all
    // went well the build script is now dead. On Windows, however, this is
    // enforced with job objects which means that it may actually be in the
    // *process* of being torn down at this point.
    //
    // Now on Windows we can't completely remove a file until all handles to it
    // have been closed. Including those that represent running processes. So if
    // we were to return here then there may still be an open reference to some
    // file in the build directory. What we want to actually do is wait for the
    // build script to *complete* exit. Take care of that by blowing away the
    // build directory here, and panicking if we eventually spin too long
    // without being able to.
    for i in 0..10 {
        match fs::remove_dir_all(&p.root().join("target")) {
            Ok(()) => return,
            Err(e) => println!("attempt {}: {}", i, e),
        }
        thread::sleep(Duration::from_millis(100));
    }

    panic!(
        "couldn't remove build directory after a few tries, seems like \
         we won't be able to!"
    );
}

#[cfg(unix)]
fn ctrl_c(child: &mut Child) {
    use libc;

    let r = unsafe { libc::kill(-(child.id() as i32), libc::SIGINT) };
    if r < 0 {
        panic!("failed to kill: {}", io::Error::last_os_error());
    }
}

#[cfg(windows)]
fn ctrl_c(child: &mut Child) {
    child.kill().unwrap();
}

// This test is similar to the above but instead tests that `cargo run` is
// configured to forward signals to children. That is, if you've executed `cargo
// run`, then ctrl-c should do whatever the child process decides to do (be it
// either die or handle it).
//
// On Unix we use the `exec` system call in `cargo run` which means that this
// happens naturally as Cargo is basically entirely out of the picture anyway.
//
// On Windows though things are more tricky. AFAIK we can't do anything on msys
// where it seems termination is un-cactchable via the winapi. We've basically
// just given up there. For `cmd.exe` though if we were to proceed as usual then
// Cargo would get killed due to its ctrl-c signal, but the child may decide
// to handle the ctrl-c and might not die. This means that we need to basically
// proactively ignore ctrl-c signals in Cargo.
#[test]
fn ctrl_c_forwarded() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let p = project()
        .file(
            "Cargo.toml",
            r#"
                [package]
                name = "foo"
                version = "0.0.1"
                authors = []
            "#,
        )
        .file(
            "src/main.rs",
            r#"
                use std::env;
                use std::io::*;
                use std::net::TcpStream;
                use std::process;

                #[cfg(unix)]
                fn main() {
                    static mut T: *mut TcpStream = 0 as *mut TcpStream;

                    extern {
                        fn signal(signum: i32, handler: extern fn(i32)) -> usize;
                    }
                    unsafe {
                        let sigint = env::args().nth(2).unwrap().parse().unwrap();
                        signal(sigint, handler);
                    }

                    extern fn handler(_: i32) {
                        unsafe {
                            drop((*T).write_all(&[2]));
                        }
                        process::exit(0);
                    }

                    let addr = env::args().nth(1).unwrap();
                    let mut socket = TcpStream::connect(&addr).unwrap();
                    unsafe {
                        T = &mut socket;
                    }
                    socket.write_all(&[1]).unwrap();
                    drop(socket.read(&mut [0; 10]));
                    panic!("that read should never return");
                }

                #[cfg(windows)]
                fn main() {
                    extern "system" {
                        fn SetConsoleCtrlHandler(
                            HandlerRoutine: usize,
                            Add: i32,
                        ) -> i32;
                        fn GenerateConsoleCtrlEvent(
                            dwCtrlEvent: u32,
                            dwProcessGroupId: u32,
                        ) -> i32;

                        fn GetProcessId() -> u32;
                    }

                    const CTRL_BREAK_EVENT: u32 = 0;

                    if env::var("YOU_ARE_THE_CHILD").is_ok() {
                        unsafe {
                            assert!(SetConsoleCtrlHandler(handler as usize, 1) != 0);
                        }

                        extern fn handler(ctrl: u32) -> i32 {
                            assert_eq!(ctrl, 0);
                            println!("signal");
                            process::exit(0);
                        }

                        println!("wait");

                        loop {
                            std::thread::sleep_ms(1000);
                        }
                    }

                    // make sure we don't die when we send ourselves a signal.
                    unsafe {
                        assert!(SetConsoleCtrlHandler(0, 1) != 0);
                    }

                    // inform the test that we've started
                    let addr = env::args().nth(1).unwrap();
                    let mut socket = TcpStream::connect(&addr).unwrap();

                    let me = std::env::current_exe().unwrap();
                    let mut child = process::Command::new(me);
                    child.env("YOU_ARE_THE_CHILD", "1");
                    let mut child = child
                        .stdout(process::Stdio::piped())
                        .spawn()
                        .unwrap();
                    let stdout = child.stdout.take().unwrap();
                    let mut stdout = std::io::BufReader::new(stdout);
                    let mut line = String::new();
                    stdout.read_line(&mut line).unwrap();
                    assert!(line.starts_with("wait"));

                    unsafe {
                        let r = GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, GetProcessId());
                        if r == 0 {
                            panic!("{}", Error::last_os_error());
                        }
                    }

                    line.truncate(0);
                    stdout.read_to_string(&mut line);
                    assert!(line.starts_with("signal"));
                    assert!(child.wait().unwrap().success());

                    socket.write_all(&[2]).unwrap();
                }
            "#
        )
        .build();

    p.cargo("build").run();
    let mut cargo = p.cargo("run -q");
    cargo.arg(addr.to_string());
    #[cfg(unix)]
    {
        use libc;
        cargo.arg(libc::SIGINT.to_string());
    }

    let mut cargo = cargo.build_command();
    cargo
        // .stdin(Stdio::piped())
        // .stdout(Stdio::piped())
        // .stderr(Stdio::piped())
        .new_process_group();
    let mut child = cargo.spawn().unwrap();

    let mut sock = listener.accept().unwrap().0;
    let mut byte = [0];

    #[cfg(unix)]
    {
        assert_eq!(sock.read(&mut byte).unwrap(), 1);
        assert_eq!(byte[0], 1);
        ctrl_c(&mut child);
    }
    // NB: windows has more of this in the executable itself

    assert!(child.wait().unwrap().success());
    assert_eq!(sock.read(&mut byte).unwrap(), 1);
    assert_eq!(byte[0], 2);
}

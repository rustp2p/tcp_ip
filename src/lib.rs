/*!
# Example
```no_run
#[tokio::main]
pub async fn main() -> std::io::Result<()> {
    use tokio::io::AsyncReadExt;
    let (ip_stack, _ip_stack_send, mut ip_stack_recv) = tcp_ip::ip_stack(tcp_ip::IpStackConfig::default())?;
    tokio::spawn(async move {
        loop {
            // ip_stack_send.send_ip_packet()
            todo!("Send IP packets to the protocol stack using 'ip_stack_send'")
        }
    });
    tokio::spawn(async move {
        let mut buf = [0; 65535];
        loop {
            match ip_stack_recv.recv(&mut buf).await {
                Ok(_len) => {}
                Err(e) => println!("{e:?}"),
            }
            todo!("Receive IP packets from the protocol stack using 'ip_stack_recv'")
        }
    });
    let mut tcp_listener = tcp_ip::tcp::TcpListener::bind(ip_stack.clone(), "0.0.0.0:80".parse().unwrap()).await?;
    loop {
        let (mut tcp_stream, addr) = tcp_listener.accept().await?;
        tokio::spawn(async move {
            let mut buf = [0; 1024];
            match tcp_stream.read(&mut buf).await {
                Ok(len) => println!("read:{:?},addr={addr}", &buf[..len]),
                Err(e) => println!("{e:?}"),
            }
        });
    }
}
```
*/

mod buffer;
pub mod icmp;
mod ip_stack;
pub use ip_stack::*;
pub mod address;
pub mod ip;
pub mod tcp;
pub mod udp;

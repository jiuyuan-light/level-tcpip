## ARCH
app -> lib(socket, connect, write)
    -> lvl-ip   -> server

    其中，tcp三次握手在lvl-ip完成，不存在阻塞问题。


## 实现

ipc_loop，和apps的所有交互都在该线程完成
netdev_tx_loop, 所有重传都在该线程完成
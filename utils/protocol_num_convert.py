import socket


table = {num: name[8:] for name,num in vars(socket).items() if name.startswith("IPPROTO")}


def proto_2_num(proto):
    if proto is None:
        return 0
    return socket.getprotobyname(proto)


def num_2_proto(num):

    return table[num]

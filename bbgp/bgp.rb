require 'bgp4r'
include BGP

Log.create
Log.level=Logger::DEBUG

neighbor = Neighbor.new \
  :version=> 4,
  :my_as=> 100,
  :remote_addr => '192.168.1.104',
  :id=> '1.1.1.1',
  :holdtime=> 20

neighbor.capability_mbgp_ipv4_unicast  
neighbor.capability_mbgp_ipv4_multicast
neighbor.capability_mbgp_ipv4_mpls_vpn_unicast
neighbor.capability_mbgp_ipv6_mpls_vpn_multicast
neighbor.capability_mbgp_nsap_mpls_vpn_unicast
neighbor.capability_mbgp_nsap_unicast  
neighbor.capability_route_refresh
neighbor.capability_route_refresh 128  
neighbor.capability_four_byte_as

neighbor.start :auto_retry=> false

